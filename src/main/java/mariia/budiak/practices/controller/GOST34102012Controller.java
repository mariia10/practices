package mariia.budiak.practices.controller;

import lombok.RequiredArgsConstructor;
import mariia.budiak.practices.model.GOST34102012;
import mariia.budiak.practices.service.GOST34102012Service;
import org.springframework.http.MediaType;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.multipart.MultipartFile;

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

    /**
     * подпись содержимого файла
     *
     * @param document для подписи
     * @return подапись в base64
     * @throws Exception
     */
    @RequestMapping(value = "/signFile", method = RequestMethod.POST,
            consumes = {MediaType.MULTIPART_FORM_DATA_VALUE})
    public String signFile(@RequestPart MultipartFile document) throws Exception {
        var bytes = service.signFile(document);
        return Base64.getEncoder().encodeToString(bytes);
    }

    /**
     * верификация подписи файла
     *
     * @param document подписанный
     * @return подапись в base64
     * @throws Exception
     */
    @RequestMapping(value = "/verifySignFile", method = RequestMethod.POST,
            consumes = {MediaType.MULTIPART_FORM_DATA_VALUE})
    public boolean decryptFile(@RequestPart MultipartFile document,
                               @RequestParam String sign) throws Exception {
        return service.verifySignedFile(document, sign);
    }


    /**
     * загрузка ключа подписи
     *
     * @return подапись в base64
     * @throws Exception
     */
    @RequestMapping(value = "/uploadPrivateKey", method = RequestMethod.POST)
    public String uploadPrivateKey(@RequestParam String privateKey) throws Exception {
        return service.uploadPrivateKey(privateKey);
    }

    /**
     * загрузка ключа подписи
     *
     * @return подапись в base64
     * @throws Exception
     */
    @RequestMapping(value = "/uploadPublicKey", method = RequestMethod.POST)
    public String uploadPublicKey(@RequestParam String publicKey) throws Exception {
        return service.uploadPublicKey(publicKey);
    }

}
