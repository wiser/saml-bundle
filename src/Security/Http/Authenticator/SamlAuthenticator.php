<?php

namespace Wiser\SamlBundle\Security\Http\Authenticator;

use Exception;
use Symfony\Component\HttpFoundation\RedirectResponse;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\Routing\Exception\RouteNotFoundException;
use Symfony\Component\Routing\Generator\UrlGeneratorInterface;
use Symfony\Component\Routing\RouterInterface;
use Symfony\Component\Security\Core\Authentication\Token\TokenInterface;
use Symfony\Component\Security\Core\Exception\AuthenticationException;
use Symfony\Component\Security\Core\Exception\CustomUserMessageAuthenticationException;
use Symfony\Component\Security\Http\Authentication\AuthenticationFailureHandlerInterface;
use Symfony\Component\Security\Http\Authentication\AuthenticationSuccessHandlerInterface;
use Symfony\Component\Security\Http\Authentication\DefaultAuthenticationSuccessHandler;
use Symfony\Component\Security\Http\Authentication\DefaultAuthenticationFailureHandler;
use Symfony\Component\Security\Http\Authenticator\AbstractAuthenticator;
use Symfony\Component\Security\Http\Authenticator\Passport\Badge\PreAuthenticatedUserBadge;
use Symfony\Component\Security\Http\Authenticator\Passport\Badge\UserBadge;
use Symfony\Component\Security\Http\Authenticator\Passport\Passport;
use Symfony\Component\Security\Http\Authenticator\Passport\SelfValidatingPassport;
use Symfony\Component\Security\Http\EntryPoint\AuthenticationEntryPointInterface;
use Symfony\Component\Security\Http\HttpUtils;
use Wiser\SamlBundle\Security\User\SamlUser;

class SamlAuthenticator extends AbstractAuthenticator implements AuthenticationEntryPointInterface
{
    /**
     * @var string Entity ID
     */
    private string $entityId;

    /**
     * @var string Identity Provider URL
     */
    private string $idpUrl;

    /**
     * @var string Login Path
     */
    private string $loginPath;

    /**
     * @var string Check Path
     */
    private string $checkPath;

    /**
     * @var \Symfony\Component\Security\Http\HttpUtils
     */
    private HttpUtils $httpUtils;

    /**
     * @var \Symfony\Component\Routing\RouterInterface
     */
    private RouterInterface $router;

    /**
     * @var \Wiser\SamlBundle\Security\SamlMessageManager
     */
    private SamlMessageManager $samlMessageManager;

    /**
     * @var \Symfony\Component\Security\Http\Authentication\AuthenticationSuccessHandlerInterface
     */
    private AuthenticationSuccessHandlerInterface $successHandler;

    /**
     * @var \Symfony\Component\Security\Http\Authentication\AuthenticationFailureHandlerInterface
     */
    private AuthenticationFailureHandlerInterface $failureHandler;

    private string $redirectTo;

    public function __construct(
        string                                $entityId,
        string                                $idpUrl,
        string                                $loginPath,
        string                                $checkPath,
        HttpUtils                             $httpUtils,
        RouterInterface                       $router,
        SamlMessageManager                    $samlMessageManager,
        AuthenticationSuccessHandlerInterface $successHandler,
        AuthenticationFailureHandlerInterface $failureHandler,
    )
    {
        $this->entityId = $entityId;
        $this->idpUrl = $idpUrl;
        $this->loginPath = $loginPath;
        $this->checkPath = $checkPath;
        $this->httpUtils = $httpUtils;
        $this->router = $router;
        $this->samlMessageManager = $samlMessageManager;
        $this->successHandler = $successHandler;
        $this->failureHandler = $failureHandler;
    }

    /**
     * Called when authentication is needed.
     * This redirects to home or to the IDP according to the configuration.
     */
    public function start(Request $request, AuthenticationException $authException = null): Response
    {
        return new RedirectResponse($this->httpUtils->generateUri($request, $this->loginPath));
    }

    /**
     * Starts the authentication by redirecting the user to IDP with a Saml request
     */
    public function login(?Request $request)
    {
        $relayState = null;
        if ($request->hasSession()) {
            $session = $request->getSession();
            $firewallName = array_slice(explode('.', trim($request->attributes->get('_firewall_context'))), -1)[0];
            $relayState = $session->get('_security.' . $firewallName . '.target_path');
        }
        $samlRequestUrl = $this->getIdpUrl($relayState);

        return new RedirectResponse($samlRequestUrl);
    }

    /**
     * @throws \Exception
     */
    private function getIdpUrl(?string $relayState): string
    {
        $samlRequest = $this->samlMessageManager->getSamlAuthenticationRequest(
            $this->entityId,
            $this->router->generate('saml_acs', [], UrlGeneratorInterface::ABSOLUTE_URL)
        );

        return sprintf(
            '%s?SAMLRequest=%s%s',
            $this->idpUrl,
            urlencode(base64_encode(gzdeflate($samlRequest))),
            $relayState ? "&RelayState=" . $relayState : ""
        );
    }

    /**
     * @inheritDoc
     */
    public function supports(Request $request): bool
    {
        return $this->httpUtils->checkRequestPath($request, $this->checkPath);
    }

    /**
     * Handles the Saml Response coming from the IDP
     */
    public function authenticate(Request $request): Passport
    {
        $samlResponse = base64_decode($request->request->get('SAMLResponse'));

        try {
            $userAttributes = $this->samlMessageManager->getUserAttributesFromSamlResponse($samlResponse);
            return new SelfValidatingPassport(
                new UserBadge(
                    $userAttributes['nameId'], // nameId is mandatory for SAML authentication
                    function ($userIdentifier) use ($userAttributes) {
                        return new SamlUser(
                            $userIdentifier,
                            $userAttributes['groups']
                        );
                    }
                ),
                [new PreAuthenticatedUserBadge()]
            );

        } catch (Exception $exception) {
            throw new CustomUserMessageAuthenticationException(
                sprintf(
                    'Une erreur est survenue durant l’authentification SAML : %s',
                    $exception->getMessage()
                )
            );
        }
    }

    /**
     * @inheritDoc
     */
    public function onAuthenticationSuccess(Request $request, TokenInterface $token, string $firewallName): ?Response
    {
        return $this->successHandler->onAuthenticationSuccess($request, $token);
    }

    /**
     * @inheritDoc
     */
    public function onAuthenticationFailure(Request $request, AuthenticationException $exception): ?Response
    {
        return $this->failureHandler->onAuthenticationFailure($request, $exception);
    }
}