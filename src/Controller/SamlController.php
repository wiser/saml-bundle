<?php

namespace Wiser\SamlBundle\Controller;

use Symfony\Bundle\FrameworkBundle\Controller\AbstractController;
use Symfony\Component\HttpFoundation\Request;
use Wiser\SamlBundle\Security\Http\Authenticator\SamlAuthenticator;

class SamlController extends AbstractController
{
    protected SamlAuthenticator $samlAuthenticator;

    public function __construct(SamlAuthenticator $samlAuthenticator)
    {
        $this->samlAuthenticator = $samlAuthenticator;
    }

    public function loginAction(Request $request)
    {
        return $this->samlAuthenticator->login($request);
    }

    public function assertionConsumerServiceAction()
    {
        throw new \RuntimeException('You must configure the check path to be handled by the firewall.');
    }
}