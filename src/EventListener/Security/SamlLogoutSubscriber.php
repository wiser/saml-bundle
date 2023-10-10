<?php

namespace Wiser\SamlBundle\EventListener\Security;

use Symfony\Component\EventDispatcher\EventSubscriberInterface;
use Symfony\Component\HttpFoundation\RedirectResponse;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\Security\Http\Event\LogoutEvent;
use Wiser\SamlBundle\Security\Http\Authenticator\SamlMessageManager;

class SamlLogoutSubscriber implements EventSubscriberInterface
{
    private string $entityId;

    private string $idpUrl;

    private SamlMessageManager $samlMessageManager;

    public function __construct(string $entityId, string $idpUrl, SamlMessageManager $samlMessageManager)
    {
        $this->entityId = $entityId;
        $this->idpUrl = $idpUrl;
        $this->samlMessageManager = $samlMessageManager;
    }

    public static function getSubscribedEvents(): array
    {
        return [LogoutEvent::class => 'onLogout'];
    }

    /**
     * @throws \Exception
     */
    public function onLogout(LogoutEvent $event): void
    {
        $samlRequest = $this->samlMessageManager->getSamlLogoutRequest(
            $this->entityId,
            $event->getToken()->getUser()->getUserIdentifier()
        );

        $event->setResponse(
            new RedirectResponse(
                sprintf(
                    '%s?SAMLRequest=%s',
                    $this->idpUrl,
                    urlencode(base64_encode(gzdeflate($samlRequest)))
                ),
                Response::HTTP_TEMPORARY_REDIRECT
            )
        );
    }
}