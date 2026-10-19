<?php
/**
 *  ------------------------------------------------------------------------
 *  samlSSO
 *
 *  samlSSO was inspired by the initial work of Derrick Smith's
 *  PhpSaml. This project's intend is to address some structural issues
 *  caused by the gradual development of GLPI and the broad amount of
 *  wishes expressed by the community.
 *
 *  Copyright (C) 2024 by Chris Gralike
 *  ------------------------------------------------------------------------
 *
 * LICENSE
 *
 * This file is part of samlSSO plugin for GLPI.
 *
 * samlSSO plugin is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * samlSSO is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU Affero General Public License for more details.
 *
 * You should have received a copy of the GNU Affero General Public License
 * along with samlSSO. If not, see <http://www.gnu.org/licenses/> or
 * https://choosealicense.com/licenses/gpl-3.0/
 *
 * ------------------------------------------------------------------------
 *
 *  @package    samlSSO
 *  @version    1.3.2
 *  @author     Chris Gralike
 *  @copyright  Copyright (c) 2024 by Chris Gralike
 *  @license    GPLv3+
 *  @see        https://github.com/DonutsNL/samlSSO/readme.md
 *  @link       https://github.com/DonutsNL/samlSSO
 *  @since      1.0.0
 * ------------------------------------------------------------------------
 **/


/** Standalone cryptographic regression tests. No real identity or persistent keys are used. */

namespace Symfony\Component\HttpFoundation {
    /** Minimal HTTP boundary doubles; the real OneLogin validation runs below. */
    class ParameterBag {
        private array $data = [];
        public function set($key, $value): void { $this->data[$key] = $value; }
        public function get($key, $default = null) { return $this->data[$key] ?? $default; }
    }
    class Request {
        public ParameterBag $attributes;
        public function __construct() { $this->attributes = new ParameterBag(); }
        public static function create(): self { return new self(); }
        public function isMethod($method): bool { return $method === 'GET'; }
    }
    class Response {
        public function __construct(public string $content, private int $status = 200, public array $headers = []) {}
        public function getStatusCode(): int { return $this->status; }
    }
    class RedirectResponse extends Response {}
}

namespace Glpi\Controller { abstract class AbstractController {} }
namespace GlpiPlugin\Samlsso { class LoginState {
 const IDP_ID='idpId'; const PHASE_LOGOFF=9;
 public function getIdpId(){return 1;} public function isSamlAuthed(){return true;}
 public function setPhase($v){$GLOBALS['phase']=$v;}
} }
namespace GlpiPlugin\Samlsso\Config { class ConfigEntity {
 public function __construct($id){ if ($id !== 1) { throw new \UnexpectedValueException('Unknown fixture provider'); } } public function isValid(){return true;}
 public function isActive(){return true;} public function getPhpSamlConfig(){return $GLOBALS['settings'];}
} }
namespace { class Session { public static function cleanOnLogout(){ $GLOBALS['cleared']=true; $_SESSION=[]; } }

require_once __DIR__ . '/../vendor/autoload.php';
require_once __DIR__ . '/../src/Controller/SamlSsoController.php';
$key=openssl_pkey_new(['private_key_bits'=>2048,'private_key_type'=>OPENSSL_KEYTYPE_RSA]);
$csr=openssl_csr_new(['commonName'=>'slo-test.invalid'],$key,['digest_alg'=>'sha256']);
$crt=openssl_csr_sign($csr,null,$key,1,['digest_alg'=>'sha256']);openssl_x509_export($crt,$cert);
$url='https://sp.example.test/marketplace/samlsso/front/logout/1';
$GLOBALS['settings']=['strict'=>true,'debug'=>false,'sp'=>['entityId'=>'https://sp.example.test/','assertionConsumerService'=>['url'=>'https://sp.example.test/acs'],'singleLogoutService'=>['url'=>$url]],'idp'=>['entityId'=>'https://idp.invalid/metadata','singleSignOnService'=>['url'=>'https://idp.invalid/sso'],'singleLogoutService'=>['url'=>'https://idp.invalid/slo'],'x509cert'=>$cert],'security'=>['wantMessagesSigned'=>true]];
function attempt($case,$edits=[], $unsigned=false, $tamper=false, $context=true, ?string $payload=null) {
 global $url,$key;
 $v=array_merge(['issuer'=>'https://idp.invalid/metadata','destination'=>$url,'name'=>'fixture-owner','index'=>'fixture-session','time'=>gmdate('Y-m-d\TH:i:s\Z')],$edits);
 $xml='<samlp:LogoutRequest xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="_fixture" Version="2.0" IssueInstant="'.$v['time'].'" Destination="'.$v['destination'].'"><saml:Issuer>'.$v['issuer'].'</saml:Issuer><saml:NameID>'.$v['name'].'</saml:NameID><samlp:SessionIndex>'.$v['index'].'</samlp:SessionIndex></samlp:LogoutRequest>';
 $enc=$payload ?? base64_encode(gzdeflate($xml));$alg='http://www.w3.org/2001/04/xmldsig-more#rsa-sha256';
 $q='SAMLRequest='.rawurlencode($enc).'&RelayState=fixture&SigAlg='.rawurlencode($alg);
 openssl_sign($q,$sig,$key,OPENSSL_ALGO_SHA256);
 if($tamper){$q=str_replace('RelayState=fixture','RelayState=changed',$q);}
 if(!$unsigned){$q.='&Signature='.rawurlencode(base64_encode($sig));}
 $_SERVER=['HTTP_HOST'=>'sp.example.test','SERVER_NAME'=>'sp.example.test','SERVER_PORT'=>'443','HTTPS'=>'on','SCRIPT_NAME'=>'/index.php','REQUEST_URI'=>'/marketplace/samlsso/front/logout/1?'.$q,'QUERY_STRING'=>$q,'REQUEST_METHOD'=>'GET'];
 parse_str($q,$_GET);$_POST=[];$_SESSION=['glpiID'=>8];
 if($context) { $_SESSION['samlsso_slo_context']=['idp'=>1,'name_id'=>'fixture-owner','session_index'=>'fixture-session']; }
 $GLOBALS['cleared']=false;
 $request=\Symfony\Component\HttpFoundation\Request::create();$request->attributes->set('idpId',1);
 $xmlErrorMode=libxml_use_internal_errors();
 $warnings=[];
 set_error_handler(static function ($severity, $message) use (&$warnings): bool {
     if (error_reporting() & $severity) { $warnings[]=$message; }
     return true;
 });
 try {
     $response=(new \GlpiPlugin\Samlsso\Controller\SamlSsoController())->slo($request);
 } finally {
     restore_error_handler();
 }
 $runtimeClean=$warnings===[] && libxml_use_internal_errors()===$xmlErrorMode && libxml_get_errors()===[];

 $ok=$case==='valid' ? $response->getStatusCode()===302 && $GLOBALS['cleared'] : $response->getStatusCode()===400 && !$GLOBALS['cleared'];
 $ok=$ok && $runtimeClean;
 echo $case.':'.($ok?'PASS':'FAIL').' status='.$response->getStatusCode().' cleared='.(int)$GLOBALS['cleared']."\n";
 if(!$ok) { echo json_encode(['warnings'=>$warnings,'mode_restored'=>libxml_use_internal_errors()===$xmlErrorMode,'xml_errors'=>count(libxml_get_errors())])."\n"; $GLOBALS['failures']++; }
}
$GLOBALS['failures']=0;
attempt('valid');attempt('unsigned',[],true);attempt('tampered',[],false,true);
attempt('wrong_name',['name'=>'other']);attempt('wrong_index',['index'=>'other']);
attempt('wrong_issuer',['issuer'=>'https://other.invalid']);attempt('wrong_destination',['destination'=>'https://other.invalid/slo']);
attempt('expired',['time'=>gmdate('Y-m-d\TH:i:s\Z',time()-600)]);attempt('missing_context',[],false,false,false);
foreach ([false,true] as $internalErrors) {
 libxml_clear_errors();
 libxml_use_internal_errors($internalErrors);
 attempt('malformed_payload_'.(int)$internalErrors,[],false,false,true,'invalid');
 attempt('truncated_xml_'.(int)$internalErrors,[],false,false,true,base64_encode(gzdeflate('<broken')));
}
libxml_use_internal_errors(false);
exit($GLOBALS['failures']?1:0);
}
