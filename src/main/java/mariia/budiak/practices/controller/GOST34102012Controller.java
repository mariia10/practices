package mariia.budiak.practices.controller;

import lombok.RequiredArgsConstructor;
import mariia.budiak.practices.model.GOST34102012;
import mariia.budiak.practices.service.GOST34102012Service;
import org.springframework.http.HttpStatus;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.client.HttpClientErrorException;

import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.Base64;

@RestController
@RequestMapping("gost34102012/")
@RequiredArgsConstructor
public class GOST34102012Controller {
    private final GOST34102012Service service;

    @RequestMapping(value = "/generateKeys", method = RequestMethod.GET)
    public GOST34102012 uploadKeys() throws Exception {
        var keys = service.genKey();
        keys.setPrivateKey(Base64.getEncoder().encodeToString(keys.getKeyPair().getPrivate().getEncoded()));
        keys.setPublicKey(Base64.getEncoder().encodeToString(keys.getKeyPair().getPublic().getEncoded()));
        return keys;
    }

    @RequestMapping(value = "/getCurrentKeys", method = RequestMethod.GET)
    public GOST34102012 getCurrentKeys() throws Exception {
        var keys = service.getKey();
        keys.setPrivateKey(Base64.getEncoder().encodeToString(keys.getKeyPair().getPrivate().getEncoded()));
        keys.setPublicKey(Base64.getEncoder().encodeToString(keys.getKeyPair().getPublic().getEncoded()));
        return keys;
    }

    @RequestMapping(value = "/signPhrase", method = RequestMethod.GET)
    public String signPhrase(@RequestParam String text) throws Exception {
        return Base64.getEncoder().encodeToString(service.sign(text.getBytes()));
    }

    @RequestMapping(value = "/verifySignPhrase", method = RequestMethod.GET)
    public Boolean verifySignPhrase(@RequestParam String text,
                                    @RequestParam String sign) throws Exception {
        return service.verify(text.getBytes(), Base64.getDecoder().decode(sign));
    }


}
