import 'dart:async';
import 'package:async/async.dart';

import 'package:grpc/grpc.dart';
import 'package:mutex/mutex.dart';
import 'package:supertokens_flutter/src/anti-csrf.dart';
import 'package:supertokens_flutter/src/constants.dart';
import 'package:supertokens_flutter/src/utilities.dart';
import 'package:supertokens_flutter/src/front-token.dart';
import 'package:supertokens_flutter/supertokens.dart';

class ResponseFutureImpl<R> extends DelegatingFuture<R>
    implements ResponseFuture<R> {
  ResponseFutureImpl() : this._(Completer<R>());

  ResponseFutureImpl._(this._result) : super(_result.future);
  Response? pendingCall;

  final Completer<R> _result;
  final _headers = Completer<Map<String, String>>();
  final _trailers = Completer<Map<String, String>>();

  void complete(ResponseFuture<R> other) {
    _result.complete(other);
    _headers.complete(other.headers);
    _trailers.complete(other.trailers);
  }

  @override
  Future<void> cancel() async {
    await pendingCall?.cancel();
  }

  @override
  Future<Map<String, String>> get headers => _headers.future;

  @override
  Future<Map<String, String>> get trailers => _trailers.future;
}

class SuperTokensGrpcInterceptor extends ClientInterceptor {
  final _refreshAPILock = ReadWriteMutex();

  @override
  ResponseFuture<R> interceptUnary<Q, R>(
    ClientMethod<Q, R> method,
    Q request,
    CallOptions options,
    ClientUnaryInvoker<Q, R> invoker,
  ) {
    final result = ResponseFutureImpl<R>();

    if (!SuperTokens.isInitCalled) {
      throw GrpcError.unauthenticated(
          'SuperTokens.init must be called before using gRPC client');
    }

    if (!shouldIntercept(method.path)) {
      final response = invoker(method, request, options);
      result.complete(response);
      return result;
    }

    () async {
      try {
        var enhancedOptions = await _addAuthHeaders(options);
        var preRequestLocalSessionState =
            await SuperTokensUtils.getLocalSessionState();

        final response = await _makeCall(
          method,
          request,
          enhancedOptions,
          invoker,
          preRequestLocalSessionState,
        );

        result.complete(response);
      } on GrpcError catch (e) {
        if (e.code == StatusCode.unauthenticated) {
          try {
            var preRequestLocalSessionState =
                await SuperTokensUtils.getLocalSessionState();
            final response = await _handleUnauthorized(
              method,
              request,
              options,
              invoker,
              preRequestLocalSessionState,
            );
            result.complete(response);
          } catch (e) {
            result._result.completeError(e);
          }
        } else {
          result._result.completeError(e);
        }
      } catch (e) {
        result._result.completeError(e);
      }
    }();

    return result;
  }

  Future<CallOptions> _addAuthHeaders(CallOptions options) async {
    Map<String, String> metadata = Map.from(options.metadata);
    LocalSessionState localSessionState =
        await SuperTokensUtils.getLocalSessionState();
    String? antiCSRFToken =
        await AntiCSRF.getToken(localSessionState.lastAccessTokenUpdate);
    if (antiCSRFToken != null) {
      metadata[antiCSRFHeaderKey] = antiCSRFToken;
    }

    String? accessToken = await Utils.getTokenForHeaderAuth(TokenType.ACCESS);
    String? refreshToken = await Utils.getTokenForHeaderAuth(TokenType.REFRESH);
    if (accessToken != null && refreshToken != null) {
      metadata['authorization'] = 'Bearer $accessToken';
    }

    metadata['st-auth-mode'] =
        SuperTokens.config.tokenTransferMethod.getValue();

    return options.mergedWith(CallOptions(metadata: metadata));
  }

  Future<ResponseFuture<R>> _makeCall<Q, R>(
    ClientMethod<Q, R> method,
    Q request,
    CallOptions options,
    ClientUnaryInvoker<Q, R> invoker,
    LocalSessionState preRequestLocalSessionState,
  ) async {
    // is this lock needed? check http implementation.
    await _refreshAPILock.acquireRead();
    try {
      final response = invoker(method, request, options);
      await _updateTokensFromMetadata(response, preRequestLocalSessionState);
      return response;
    } finally {
      _refreshAPILock.release();
    }
  }

  Future<void> _updateTokensFromMetadata(
    ResponseFuture response,
    LocalSessionState preRequestLocalSessionState,
  ) async {
    final metadata = await response.trailers;

    // purpose of front-token: https://community.supertokens.com/t/12094847/hey-everyone-is-there-a-page-in-documentation-explaining-how
    // base64 encoding of access token's payload used for cookie-based auth
    String? frontToken = metadata[frontTokenHeaderKey];
    if (frontToken != null) {
      await FrontToken.setItem(frontToken);
    }

    String? antiCSRFToken = metadata[antiCSRFHeaderKey];
    if (antiCSRFToken != null) {
      await AntiCSRF.setToken(
        antiCSRFToken,
        preRequestLocalSessionState.lastAccessTokenUpdate,
      );
    }

    String? accessToken = metadata[ACCESS_TOKEN_NAME];
    if (accessToken != null) {
      await Utils.setToken(TokenType.ACCESS, accessToken);
    }

    String? refreshToken = metadata[REFRESH_TOKEN_NAME];
    if (refreshToken != null) {
      await Utils.setToken(TokenType.REFRESH, refreshToken);
    }
  }

  Future<ResponseFuture<R>> _handleUnauthorized<Q, R>(
    ClientMethod<Q, R> method,
    Q request,
    CallOptions options,
    ClientUnaryInvoker<Q, R> invoker,
    LocalSessionState preRequestLocalSessionState,
  ) async {
    await _refreshAPILock.acquireWrite();
    try {
      final UnauthorisedResponse shouldRetry =
          await onUnauthorisedResponse(preRequestLocalSessionState);

      if (shouldRetry.status == UnauthorisedStatus.RETRY) {
        final newOptions = await _addAuthHeaders(options);
        return await _makeCall(
          method,
          request,
          newOptions,
          invoker,
          preRequestLocalSessionState,
        );
      }

      if (shouldRetry.exception != null) {
        throw GrpcError.unauthenticated(shouldRetry.exception!.message);
      }

      throw GrpcError.unauthenticated('Session expired');
    } finally {
      _refreshAPILock.release();
    }
  }

  bool shouldIntercept(String path) {
    if (SuperTokensUtils.getApiDomain(path) != SuperTokens.config.apiDomain) {
      return false;
    }

    if (path == SuperTokens.refreshTokenUrl) {
      return false;
    }

    if (!Utils.shouldDoInterceptions(path, SuperTokens.config.apiDomain,
        SuperTokens.config.sessionTokenBackendDomain)) {
      return false;
    }

    return true;
  }

  Future<UnauthorisedResponse> onUnauthorisedResponse(
    LocalSessionState preRequestLocalSessionState,
    ClientChannel channel,
  ) async {
    try {
      await _refreshAPILock.acquireWrite();

      LocalSessionState postLockLocalSessionState =
          await SuperTokensUtils.getLocalSessionState();

      if (postLockLocalSessionState.status ==
          LocalSessionStateStatus.NOT_EXISTS) {
        SuperTokens.config.eventHandler(Eventype.UNAUTHORISED);
        return UnauthorisedResponse(status: UnauthorisedStatus.SESSION_EXPIRED);
      }

      // Check if session state changed while waiting for lock
      if (postLockLocalSessionState.status !=
              preRequestLocalSessionState.status ||
          (postLockLocalSessionState.status == LocalSessionStateStatus.EXISTS &&
              preRequestLocalSessionState.status ==
                  LocalSessionStateStatus.EXISTS &&
              postLockLocalSessionState.lastAccessTokenUpdate !=
                  preRequestLocalSessionState.lastAccessTokenUpdate)) {
        return UnauthorisedResponse(status: UnauthorisedStatus.RETRY);
      }

      // Create metadata for refresh call
      var metadata = <String, String>{};

      if (preRequestLocalSessionState.status ==
          LocalSessionStateStatus.EXISTS) {
        String? antiCSRFToken = await AntiCSRF.getToken(
            preRequestLocalSessionState.lastAccessTokenUpdate);
        if (antiCSRFToken != null) {
          metadata[antiCSRFHeaderKey] = antiCSRFToken;
        }
      }

      // Add required headers
      metadata['rid'] = SuperTokens.rid;
      metadata['fdi-version'] = Version.supported_fdi.join(',');

      String? refreshToken =
          await Utils.getTokenForHeaderAuth(TokenType.REFRESH);
      if (refreshToken != null) {
        metadata['authorization'] = 'Bearer $refreshToken';
      }

      SuperTokensTokenTransferMethod tokenTransferMethod =
          SuperTokens.config.tokenTransferMethod;
      metadata['st-auth-mode'] = tokenTransferMethod.getValue();

      // Create call options with metadata
      final options = CallOptions(metadata: metadata);

      // Make refresh token call using gRPC
      // Note: You'll need to define this method according to your proto definition
      final stub = RefreshServiceClient(channel);

      try {
        final response = await stub.refresh(
          RefreshRequest(), // Or whatever request object your proto defines
          options: options,
        );

        // Update tokens from response metadata
        final responseMetadata = await response.trailers;

        String? frontTokenInMetadata = responseMetadata[frontTokenHeaderKey];
        if (responseMetadata
                .containsKey(StatusCode.unauthenticated.toString()) &&
            frontTokenInMetadata == null) {
          await FrontToken.setItem("remove");
        }

        // Save tokens from metadata
        await _updateTokensFromMetadata(response, preRequestLocalSessionState);

        SuperTokensUtils.fireSessionUpdateEventsIfNecessary(
          wasLoggedIn: preRequestLocalSessionState.status ==
              LocalSessionStateStatus.EXISTS,
          status: StatusCode.ok.value,
          frontTokenFromResponse: frontTokenInMetadata,
        );

        if ((await SuperTokensUtils.getLocalSessionState()).status ==
            LocalSessionStateStatus.NOT_EXISTS) {
          return UnauthorisedResponse(
              status: UnauthorisedStatus.SESSION_EXPIRED);
        }

        SuperTokens.config.eventHandler(Eventype.REFRESH_SESSION);
        return UnauthorisedResponse(status: UnauthorisedStatus.RETRY);
      } on GrpcError catch (e) {
        if (e.code == StatusCode.unauthenticated) {
          return UnauthorisedResponse(
            status: UnauthorisedStatus.API_ERROR,
            error: GrpcError.unauthenticated(
                "Refresh API returned unauthenticated status"),
          );
        }
        return UnauthorisedResponse(
          status: UnauthorisedStatus.API_ERROR,
          error: GrpcError.unknown("Refresh API failed: ${e.message}"),
        );
      }
    } catch (e) {
      return UnauthorisedResponse(
        status: UnauthorisedStatus.API_ERROR,
        error: GrpcError.unknown("Failed to refresh session: $e"),
      );
    } finally {
      _refreshAPILock.release();
    }
  }
}

enum UnauthorisedStatus {
  SESSION_EXPIRED,
  API_ERROR,
  RETRY,
}

class UnauthorisedResponse {
  final UnauthorisedStatus status;
  final Exception? error;
  final GrpcError? exception; // Changed from http.ClientException to GrpcError

  UnauthorisedResponse({
    required this.status,
    this.error,
    this.exception,
  });
}
