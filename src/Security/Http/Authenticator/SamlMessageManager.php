<?php

namespace Wiser\SamlBundle\Security\Http\Authenticator;

use DateTimeImmutable;
use DateTimeZone;
use DOMDocument;
use DOMXPath;
use Exception;

class SamlMessageManager
{
    const SAML_SUCCESS_STATUS_CODE = 'urn:oasis:names:tc:SAML:2.0:status:Success';

    // Identifiant unique utilisé pour les échanges SAML
    const SAML_CLAIMS_TOKEN_IDENTIFIER = 'http://schemas.xmlsoap.org/ws/2005/05/identity/claims/name';

        // Nom de famille
    const SAML_CLAIMS_TOKEN_SURNAME = 'http://schemas.xmlsoap.org/ws/2005/05/identity/claims/surname';

    // Prénom
    const SAML_CLAIMS_TOKEN_GIVEN_NAME = 'http://schemas.xmlsoap.org/ws/2005/05/identity/claims/givenname';

    // Nom complet
    const SAML_CLAIMS_TOKEN_DISPLAY_NAME = 'http://schemas.microsoft.com/identity/claims/displayname';

    // Adresse email
    const SAML_CLAIMS_TOKEN_EMAIL_ADDRESS = 'http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress';

    // Groupes d’appartenance
    const SAML_CLAIMS_TOKEN_GROUPS = 'http://schemas.microsoft.com/ws/2008/06/identity/claims/groups';

    // Rôles
    const SAML_CLAIMS_TOKEN_ROLES = 'http://schemas.xmlsoap.org/ws/2005/05/identity/claims/role';

    /**
     * @throws \Exception
     */
    public function getSamlAuthenticationRequest(string $entityId, string $loginUrl, string $prefixId = 'id'): string
    {
        $samlRequest = <<<EOL
<samlp:AuthnRequest
    xmlns="urn:oasis:names:tc:SAML:2.0:metadata"
    ID="%s"
    Version="2.0" IssueInstant="%s"
    xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"
    AssertionConsumerServiceURL="%s"
>
    <Issuer xmlns="urn:oasis:names:tc:SAML:2.0:assertion">%s</Issuer>
</samlp:AuthnRequest>
EOL;

        return sprintf(
            $samlRequest,
            uniqid($prefixId),
            (new DateTimeImmutable('now', new DateTimeZone('UTC')))->format('c'),
            $loginUrl,
            $entityId
        );
    }

    /**
     * @param string $entityId
     * @param string $userNameId
     * @param string $prefixId
     * @return string
     * @throws \Exception
     */
    public function getSamlLogoutRequest(string $entityId, string $userNameId, string $prefixId = 'id'): string
    {
        $samlRequest = <<<EOL
<samlp:LogoutRequest 
    xmlns="urn:oasis:names:tc:SAML:2.0:metadata" 
    ID="%s" 
    Version="2.0" 
    IssueInstant="%s" 
    xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"
>
    <Issuer xmlns="urn:oasis:names:tc:SAML:2.0:assertion">%s</Issuer>
    <NameID xmlns="urn:oasis:names:tc:SAML:2.0:assertion">%s</NameID>
</samlp:LogoutRequest>
EOL;

        return sprintf(
            $samlRequest,
            uniqid($prefixId),
            (new DateTimeImmutable('now', new DateTimeZone('UTC')))->format('c'),
            $entityId,
            $userNameId
        );
    }

    /**
     * @throws \Exception
     */
    public function getUserAttributesFromSamlResponse(string $samlResponse): array
    {
        $this->checkSamlResponse($samlResponse);
        $xml = simplexml_load_string($samlResponse);
        $userProperties = [];
        $userProperties['extraFields'] = [];

        // Get specific NameID attribute to allow logout and other SAML communications
        $userProperties['nameId'] = (string)$xml->Assertion->Subject->NameID;

        // Get claim attributes
        foreach($xml->Assertion->AttributeStatement->children() as $child) {
            $properties = explode('/', (string)$child['Name']);
            $property = end($properties);
            switch ($property) {
                case 'displayname':
                case 'givenname':
                case 'surname':
                case 'emailaddress':
                case 'name':
                    $userProperties[$property] = (string)$child->AttributeValue;
                    break;
                case 'groups':
                    $userProperties['groups'] = [];
                    foreach ($child->AttributeValue as $group) {
                        $userProperties['groups'][] = $this->normalizeGroupName($group);
                    }
                    break;
                default:
                    $userProperties['extraFields'][$property] = (string)$child->AttributeValue;
                    break;
            }
        }
        return $userProperties;
    }

    /**
     * @throws \Exception
     */
    private function checkSamlResponse(string $samlResponse): void
    {
        $xmlDoc = new DOMDocument();
        $xmlDoc->loadXML($samlResponse);
        $xpath = new DOMXPath($xmlDoc);

        $xpath->registerNamespace('samlp', 'urn:oasis:names:tc:SAML:2.0:protocol');
        $xpath->registerNamespace('assertion', 'urn:oasis:names:tc:SAML:2.0:assertion');
        $xpath->registerNamespace('secdsig', 'http://www.w3.org/2000/09/xmldsig#');

        // fetch assertion node from XML
        $query = "/samlp:Response/assertion:Assertion";
        $nodeset = $xpath->query($query);
        $assertionNode = $nodeset->item(0);

        // fetch conditions dates from XML
        $query = "./assertion:Conditions/@NotBefore";
        $nodeset = $xpath->query($query, $assertionNode);
        $notBeforeDate = DateTimeImmutable::createFromFormat(
            'Y-m-d\TH:i:s.v\Z',
            $nodeset->item(0)->nodeValue,
            new DateTimeZone('UTC')
        );
        $query = "./assertion:Conditions/@NotOnOrAfter";
        $nodeset = $xpath->query($query, $assertionNode);
        $notOnOrAfter = DateTimeImmutable::createFromFormat(
            'Y-m-d\TH:i:s.v\Z',
            $nodeset->item(0)->nodeValue,
            new DateTimeZone('UTC')
        );

        // Check dates conditions
        $now = new DateTimeImmutable('now');
        if ($now >= $notOnOrAfter or $notBeforeDate >= $now) {
            throw new Exception('Unmatching SAML response dates conditions');
        }

        // create a new document to check the Digest
        $digestedDocumentPart = new DOMDocument();
        $digestedAssertionNode = $digestedDocumentPart->importNode($assertionNode, true);
        $digestedAssertionNode->removeChild(
            $digestedAssertionNode->getElementsByTagNameNS('http://www.w3.org/2000/09/xmldsig#', 'Signature')[0]
        );
        $digestedDocumentPart->appendChild($digestedAssertionNode);
        $digestedInfoNodeCanonicalized = $digestedAssertionNode->C14N(true);

        // fetch Signature node from XML
        $query = "./secdsig:Signature";
        $nodeset = $xpath->query($query, $assertionNode);
        $signatureNode = $nodeset->item(0);

        // fetch SignedInfo node from XML
        $query = "./secdsig:SignedInfo";
        $nodeset = $xpath->query($query, $signatureNode);
        $signedInfoNode = $nodeset->item(0);

        // fetch Digest from XML
        $query = "./secdsig:Reference/secdsig:DigestValue";
        $nodeset = $xpath->query($query, $signedInfoNode);
        $digest = $nodeset->item(0)->nodeValue;

        if (strcmp(
                $digest,
                base64_encode(hex2bin(hash('sha256', $digestedInfoNodeCanonicalized)))
            ) !== 0) {
            throw new Exception('Bad SAML response digest');
        }

        // canonicalize SignedInfo using the method described in
        // ./secdsig:SignedInfo/secdsig:CanonicalizationMethod/@Algorithm
        $signedInfoNodeCanonicalized = $signedInfoNode->C14N(true);

        // fetch the x509 certificate from XML
        $query = 'string(./secdsig:KeyInfo/secdsig:X509Data/secdsig:X509Certificate)';
        $x509cert = $xpath->evaluate($query, $signatureNode);
        // we have to re-wrap the certificate from XML to respect the PEM standard
        $x509cert = "-----BEGIN CERTIFICATE-----\n"
            . $x509cert . "\n"
            . "-----END CERTIFICATE-----";
        // fetch public key from x509 certificate
        $publicKey = openssl_get_publickey($x509cert);
        //var_dump($publicKey);

        // fetch the signature from XML
        $query = 'string(./secdsig:SignatureValue)';
        $signature = base64_decode($xpath->evaluate($query, $signatureNode));

        // verify the signature
        if (1 !== openssl_verify($signedInfoNodeCanonicalized, $signature, $publicKey, OPENSSL_ALGO_SHA256)) {
            throw new Exception('Bad SAML response signature');
        }

        // verify response status code
        $query = '/samlp:Response/samlp:Status/samlp:StatusCode/@Value';
        $nodeset = $xpath->query($query);
        $statusCode = $nodeset->item(0)->nodeValue;

        if ($statusCode !== self::SAML_SUCCESS_STATUS_CODE) {
            throw new Exception('Error from SAML identity provider');
        }
    }

    /**
     * @param string $groupName
     * @return string
     */
    private function normalizeGroupName(string $groupName): string
    {
        return 'ROLE_' . str_replace(['GRP-', '-'], ['', '_'], $groupName);
    }
}