import 'package:grpc/grpc.dart';
import 'package:mutex/mutex.dart';
import 'package:supertokens_flutter/src/anti-csrf.dart';
import 'package:supertokens_flutter/src/constants.dart';
import 'package:supertokens_flutter/src/utilities.dart';
import 'package:supertokens_flutter/src/front-token.dart';
import 'package:supertokens_flutter/supertokens.dart';

class SuperTokensGrpcInterceptor extends ClientInterceptor {
  final _refreshAPILock = ReadWriteMutex();
  
  @override
  ResponseFuture<R> interceptUnary<Q, R>(
    ClientMethod<Q, R> method,
    Q request,
    CallOptions options,
    ClientUnaryInvoker<Q, R> invoker,
  ) async {
    if (!SuperTokens.isInitCalled) {
      throw GrpcError.unauthenticated('SuperTokens.init must be called before using gRPC client');
    }

    // Skip if not matching API domain or refresh token URL
    if (!shouldIntercept(method.path)) {
      return invoker(method, request, options);
    }

    var enhancedOptions = await _addAuthHeaders(options);
    var preRequestLocalSessionState = await SuperTokensUtils.getLocalSessionState();

    try {
      return await _makeCall(
        method,
        request,
        enhancedOptions,
        invoker,
        preRequestLocalSessionState,
      );
    } on GrpcError catch (e) {
      if (e.code == StatusCode.unauthenticated) {
        return await _handleUnauthorized(
          method,
          request,
          options,
          invoker,
          preRequestLocalSessionState,
        );
      }
      rethrow;
    }
  }

  Future<CallOptions> _addAuthHeaders(CallOptions options) async {
    Map<String, String> metadata = Map.from(options.metadata);

    // Add anti-CSRF token if exists
    LocalSessionState localSessionState = await SuperTokensUtils.getLocalSessionState();
    String? antiCSRFToken = await AntiCSRF.getToken(localSessionState.lastAccessTokenUpdate);
    if (antiCSRFToken != null) {
      metadata[antiCSRFHeaderKey] = antiCSRFToken;
    }

    // Add authorization if required
    String? accessToken = await Utils.getTokenForHeaderAuth(TokenType.ACCESS);
    String? refreshToken = await Utils.getTokenForHeaderAuth(TokenType.REFRESH);
    if (accessToken != null && refreshToken != null) {
      metadata['authorization'] = 'Bearer $accessToken';
    }

    // Add token transfer method
    metadata['st-auth-mode'] = SuperTokens.config.tokenTransferMethod.getValue();

    return options.mergedWith(CallOptions(metadata: metadata));
  }

  Future<ResponseFuture<R>> _makeCall<Q, R>(
    ClientMethod<Q, R> method,
    Q request,
    CallOptions options,
    ClientUnaryInvoker<Q, R> invoker,
    LocalSessionState preRequestLocalSessionState,
  ) async {
    await _refreshAPILock.acquireRead();
    try {
      final response = await invoker(method, request, options);
      
      // Update tokens from metadata if present
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
    final metadata = response.trailers;
    
    // Update front token if present
    String? frontToken = metadata?[frontTokenHeaderKey];
    if (frontToken != null) {
      await FrontToken.setItem(frontToken);
    }

    // Update anti-CSRF token if present
    String? antiCSRFToken = metadata?[antiCSRFHeaderKey];
    if (antiCSRFToken != null) {
      await AntiCSRF.setToken(
        antiCSRFToken,
        preRequestLocalSessionState.lastAccessTokenUpdate,
      );
    }

    // Update access and refresh tokens if present
    String? accessToken = metadata?[ACCESS_TOKEN_NAME];
    if (accessToken != null) {
      await Utils.setToken(TokenType.ACCESS, accessToken);
    }

    String? refreshToken = metadata?[REFRESH_TOKEN_NAME];
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
          await Client.onUnauthorisedResponse(preRequestLocalSessionState);

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

    if (!Utils.shouldDoInterceptions(
      path,
      SuperTokens.config.apiDomain,
      SuperTokens.config.sessionTokenBackendDomain)) {
      return false;
    }

    return true;
  }
}