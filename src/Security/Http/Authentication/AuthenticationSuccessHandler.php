<?php

namespace Wiser\SamlBundle\Security\Http\Authentication;

use Psr\Log\LoggerInterface;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\Security\Http\Authentication\DefaultAuthenticationSuccessHandler;
use Symfony\Component\Security\Http\HttpUtils;

class AuthenticationSuccessHandler extends DefaultAuthenticationSuccessHandler
{
    protected function determineTargetUrl(Request $request): string
    {
        $relayState = $request->request->get('RelayState');
        if (!empty($relayState)) {
            if ($relayState !== $this->httpUtils->generateUri($request, $this->options['login_path'])) {
                return $relayState;
            }
        }

        return parent::determineTargetUrl($request);
    }
}