//
//  SuperTokensURLProtocol.swift
//  SuperTokensSession
//
//  Created by Nemi Shah on 30/09/22.
//

@preconcurrency import Foundation
#if canImport(FoundationNetworking)
@preconcurrency import FoundationNetworking
#endif

@preconcurrency public class SuperTokensURLProtocol: URLProtocol, @unchecked Sendable {
    private static let readWriteDispatchQueue = DispatchQueue(label: "io.supertokens.session.readwrite", attributes: .concurrent)
    private var sessionRefreshAttempts = 0
    
    // Refer to comment in makeRequest to know why this is needed
    private var requestForRetry: URLRequest? = nil
    
    public required override init(request: URLRequest, cachedResponse: CachedURLResponse?, client: URLProtocolClient?) {
        super.init(request: request, cachedResponse: cachedResponse, client: client)
    }
    
    public override class func canInit(with request: URLRequest) -> Bool {
        if !SuperTokens.isInitCalled {
            // We cannot throw in this function because that would be an invalid override
            // In this case we need to rely on printing instead
            print("SuperTokens Error: SuperTokens.init has not been called")
            return false
        }
        
        // We only return true if we will be intercepting this request,
        // otherwise let normal execution continue
        //
        // NOTE: For iOS we dont check whether the request is being made for refreshing
        // because we use a custom URL session object so this protocol never gets called
        do {
            let doNotDoInterception = !(try Utils.shouldDoInterception(toCheckURL: request.url!.absoluteString, apiDomain: SuperTokens.config!.apiDomain, cookieDomain: SuperTokens.config!.sessionTokenBackendDomain))
            
            if !doNotDoInterception {
                // Returning true means that URLSession will use this class when making the request
                // Note: The system tries to call this function for all registered classes in order of registration
                return true
            }
            
        } catch {
            // No-op
        }
        
        // Returning false means the iOS will not use this class for this request
        return false
    }
    
    public override class func canonicalRequest(for request: URLRequest) -> URLRequest {
        return request
    }
    
    public override func startLoading() {
        scheduleMakeRequest()
    }
    
    private func scheduleMakeRequest() {
        // we have a read write lock here. We take a read lock while making a request and a write lock while refreshing
        // because if we don't do that, then there may be a race condition where we may read a new id refresh token from storage
        // but the cookies may still be the older ones.
        SuperTokensURLProtocol.readWriteDispatchQueue.async { [weak self] in
            guard let self else { return }
            self.makeRequest()
        }
    }
    
    private func removeAuthHeaderIfMatchesLocalToken(_ request: URLRequest) -> URLRequest {
        var updatedRequest = request
        // .value is case insensitive
        if let originalAuthorizationHeader = updatedRequest.value(forHTTPHeaderField: "Authorization") {
            let accessToken = Utils.getTokenForHeaderAuth(tokenType: .access)
            let refreshToken = Utils.getTokenForHeaderAuth(tokenType: .refresh)
            
            if accessToken != nil && refreshToken != nil && originalAuthorizationHeader == "Bearer \(accessToken!)" {
                // Removing headers from a request is not case insensitive
                updatedRequest.setValue(nil, forHTTPHeaderField: "Authorization")
                updatedRequest.setValue(nil, forHTTPHeaderField: "authorization")
            }
        }
        
        return updatedRequest
    }
    
    func makeRequest() {
        var requestToSend = requestForRetry ?? self.request
        requestForRetry = nil
        
        requestToSend = removeAuthHeaderIfMatchesLocalToken(requestToSend)
        let preRequestLocalSessionState = Utils.getLocalSessionState()
        
        if preRequestLocalSessionState.status == .EXISTS {
            let antiCSRF = AntiCSRF.getToken(associatedAccessTokenUpdate: preRequestLocalSessionState.lastAccessTokenUpdate!)
            if antiCSRF != nil {
                requestToSend.setValue(antiCSRF!, forHTTPHeaderField: SuperTokensConstants.antiCSRFHeaderKey)
            }
        }
        
        if requestToSend.value(forHTTPHeaderField: "rid") == nil {
            requestToSend.addValue("anti-csrf", forHTTPHeaderField: "rid")
        }
        
        let tokenTransferMethod = SuperTokens.config!.tokenTransferMethod
        requestToSend.setValue(tokenTransferMethod.rawValue, forHTTPHeaderField: "st-auth-mode")
        
        Utils.setAuthorizationHeaderIfRequired(request: &requestToSend)
        
        let apiRequest = requestToSend
        
        // We need to use a custom URLSession here because otherwise it will use this protocol, causing an infinite loop
        let customSession = URLSession(configuration: URLSessionConfiguration.default)
        customSession.dataTask(with: apiRequest, completionHandler: { [weak self] data, response, error in
            guard let self else { return }
            
            if let httpResponse = response as? HTTPURLResponse {
                Utils.saveTokenFromHeaders(httpResponse: httpResponse)
                Utils.fireSessionUpdateEventsIfNecessary(
                    wasLoggedIn: preRequestLocalSessionState.status == .EXISTS,
                    status: httpResponse.statusCode,
                    frontTokenheaderFromResponse: httpResponse.value(forHTTPHeaderField: SuperTokensConstants.frontTokenHeaderKey)
                )
                
                if httpResponse.statusCode == SuperTokens.config!.sessionExpiredStatusCode {
                    /**
                    * An API may return a 401 error response even with a valid session, causing a session refresh loop in the interceptor.
                    * To prevent this infinite loop, we break out of the loop after retrying the original request a specified number of times.
                    * The maximum number of retry attempts is defined by maxRetryAttemptsForSessionRefresh config variable.
                    */
                    if self.sessionRefreshAttempts >= SuperTokens.config!.maxRetryAttemptsForSessionRefresh {
                        let errorMessage = "Error: Received 401 response from \(String(describing: apiRequest.url)). After refreshing the session and retrying the request \(SuperTokens.config!.maxRetryAttemptsForSessionRefresh ) times, we still received 401 responses. Maximum session refresh limit reached. Breaking out of the refresh loop. Please investigate your API. Consider increasing maxRetryAttemptsForSessionRefresh in the config if needed."
                        print(errorMessage)
                        self.resolveToUser(data: nil, response: nil, error: SuperTokensError.maxRetryAttemptsReachedForSessionRefresh(message: errorMessage))
                        return
                    }
                    
                    let retryReadyRequest = self.removeAuthHeaderIfMatchesLocalToken(apiRequest)
                    let unauthResponse = SuperTokensURLProtocol.onUnauthorisedResponse(preRequestLocalSessionState: preRequestLocalSessionState)

                    self.sessionRefreshAttempts += 1

                    if unauthResponse.status == .RETRY {
                        self.requestForRetry = retryReadyRequest
                        self.scheduleMakeRequest()
                    } else {
                        if unauthResponse.error != nil {
                            self.resolveToUser(data: nil, response: nil, error: unauthResponse.error)
                        } else {
                            self.resolveToUser(data: data, response: response, error: unauthResponse.error)
                        }
                    }
                } else {
                    self.resolveToUser(data: data, response: response, error: error)
                }
            } else {
                self.resolveToUser(data: data, response: response, error: error)
            }
        }).resume()
    }
    
    func resolveToUser(data: Data?, response: URLResponse?, error: Error?) {
        // This will call the appropriate callbacks and return the data back to the user
        if error != nil {
            self.client?.urlProtocol(self, didFailWithError: error!)
        }
        
        if data != nil {
            self.client?.urlProtocol(self, didLoad: data!)
        }
        
        if response != nil {
            self.client?.urlProtocol(self, didReceive: response!, cacheStoragePolicy: .notAllowed)
        }
        
        // After everything, we need to call this to indicate to URLSession that this protocol has finished its task
        self.client?.urlProtocolDidFinishLoading(self)
    }
    
    static func onUnauthorisedResponse(preRequestLocalSessionState: LocalSessionState) -> UnauthorisedResponse {
        SuperTokensURLProtocol.readWriteDispatchQueue.sync(flags: .barrier) {
            let postLockLocalSessionState = Utils.getLocalSessionState()

            if postLockLocalSessionState.status == .NOT_EXISTS {
                SuperTokens.config!.eventHandler(.UNAUTHORISED)
                return UnauthorisedResponse(status: .SESSION_EXPIRED, error: nil)
            }

            if postLockLocalSessionState.status != preRequestLocalSessionState.status || (postLockLocalSessionState.status == .EXISTS && preRequestLocalSessionState.status == .EXISTS && postLockLocalSessionState.lastAccessTokenUpdate! != preRequestLocalSessionState.lastAccessTokenUpdate!) {
                return UnauthorisedResponse(status: .RETRY, error: nil)
            }

            let refreshUrl = URL(string: SuperTokens.refreshTokenUrl)!
            var refreshRequest = URLRequest(url: refreshUrl)
            refreshRequest.httpMethod = "POST"

            if preRequestLocalSessionState.status == .EXISTS {
                if let antiCSRF = AntiCSRF.getToken(associatedAccessTokenUpdate: preRequestLocalSessionState.lastAccessTokenUpdate!) {
                    refreshRequest.addValue(antiCSRF, forHTTPHeaderField: SuperTokensConstants.antiCSRFHeaderKey)
                }
            }

            refreshRequest.addValue(SuperTokens.rid, forHTTPHeaderField: "rid")
            refreshRequest.addValue(Version.supported_fdi.joined(separator: ","), forHTTPHeaderField: "fdi-version")

            let tokenTransferMethod = SuperTokens.config!.tokenTransferMethod
            refreshRequest.setValue(tokenTransferMethod.rawValue, forHTTPHeaderField: "st-auth-mode")

            Utils.setAuthorizationHeaderIfRequired(request: &refreshRequest, addRefreshToken: true)

            refreshRequest = SuperTokens.config!.preAPIHook(.REFRESH_SESSION, refreshRequest)

            let refreshApiRequest = refreshRequest

            let semaphore = DispatchSemaphore(value: 0)
            var unauthResponse = UnauthorisedResponse(status: .API_ERROR, error: SuperTokensError.apiError(message: "Refresh session request timed out"))

            // We need to use a custom URLSession here because otherwise it will use this protocol, causing an infinite loop
            let customSession = URLSession(configuration: URLSessionConfiguration.default)
            let refreshTask = customSession.dataTask(with: refreshApiRequest, completionHandler: { data, response, error in

                if let httpResponse = response as? HTTPURLResponse {
                    Utils.saveTokenFromHeaders(httpResponse: httpResponse)

                    let isUnauthorised = httpResponse.statusCode == SuperTokens.config!.sessionExpiredStatusCode

                    if isUnauthorised && httpResponse.value(forHTTPHeaderField: SuperTokensConstants.frontTokenHeaderKey) == nil {
                        FrontToken.setItem(frontToken: "remove")
                    }

                    let frontTokenInHeaders = httpResponse.value(forHTTPHeaderField: SuperTokensConstants.frontTokenHeaderKey)

                    Utils.fireSessionUpdateEventsIfNecessary(
                        wasLoggedIn: preRequestLocalSessionState.status == .EXISTS,
                        status: httpResponse.statusCode,
                        frontTokenheaderFromResponse: frontTokenInHeaders ?? "remove"
                    )

                    if httpResponse.statusCode >= 300 {
                        unauthResponse = UnauthorisedResponse(
                            status: .API_ERROR,
                            error: SuperTokensError.apiError(message: "refresh session call failed with status code: \(httpResponse.statusCode)")
                        )
                        semaphore.signal()
                        return
                    }

                    SuperTokens.config!.postAPIHook(.REFRESH_SESSION, refreshApiRequest, response)

                    if Utils.getLocalSessionState().status == .NOT_EXISTS {
                        unauthResponse = UnauthorisedResponse(status: .SESSION_EXPIRED, error: nil)
                        semaphore.signal()
                        return
                    }

                    SuperTokens.config!.eventHandler(.REFRESH_SESSION)
                }

                if let error {
                    unauthResponse = UnauthorisedResponse(status: .API_ERROR, error: error)
                    semaphore.signal()
                    return
                }

                Utils.saveLastAccessTokenUpdate()
                unauthResponse = UnauthorisedResponse(status: .RETRY, error: nil)

                semaphore.signal()

            })

            refreshTask.resume()

            if semaphore.wait(timeout: .now() + 15) == .timedOut {
                refreshTask.cancel()
                return UnauthorisedResponse(status: .API_ERROR, error: SuperTokensError.apiError(message: "Refresh session request timed out"))
            }

            return unauthResponse
        }
    }

    public override func stopLoading() {
        // Do nothing, this is required to be implemented
    }
}
