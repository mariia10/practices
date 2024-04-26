package mariia.budiak.practices.controller;

import io.swagger.annotations.*;
import lombok.RequiredArgsConstructor;
import mariia.budiak.practices.model.AffineKey;
import mariia.budiak.practices.service.AESService;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.client.HttpClientErrorException;
import org.springframework.web.multipart.MultipartFile;

import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.Base64;

@RestController
@RequestMapping("aes/")
@RequiredArgsConstructor
public class AESController {

    private final AESService service;


    @RequestMapping(value = "/uploadKey", method = RequestMethod.POST)
    public void uploadKey(@RequestParam String key) {
        if (key == null || (key.length() != 16 &&
                key.length() != 24 && key.length() != 32)) {
            throw new HttpClientErrorException(HttpStatus.BAD_REQUEST,
                    "задан невалидный ключ " +
                            "- он должен содержать 16, 24 или 32 символа");
        }
        service.uploadKey(key);
    }

    @RequestMapping(value = "/encrypt", method = RequestMethod.GET)
    public String encrypt(@RequestParam String key) {
        return Base64.getEncoder().encodeToString(service.encryptECB(
                service.fillBlock(key).getBytes()));
    }

    @RequestMapping(value = "/decrypt", method = RequestMethod.GET)
    public String decCrypt(@RequestParam String key) {
        return new String(service.decryptECB(Base64.getDecoder().decode(key)));
    }

    @RequestMapping(value = "/encryptFile", method = RequestMethod.POST, consumes = {MediaType.MULTIPART_FORM_DATA_VALUE})
    public HttpEntity<byte[]> encryptFile(@RequestPart MultipartFile document) {
        var bytes = service.encryptECBFile(document);
        if (bytes == null) throw new HttpClientErrorException(HttpStatus.NOT_FOUND);
        HttpHeaders header = new HttpHeaders();
        header.setContentType(MediaType.APPLICATION_OCTET_STREAM);
        header.set(HttpHeaders.CONTENT_DISPOSITION, "attachment; filename=" + String.format("%s_%s",
                document.getName(), "encrypted.txt"));
        header.setContentLength(bytes.length);
        return new HttpEntity<byte[]>(bytes, header);
    }

    @RequestMapping(value = "/decryptFile", method = RequestMethod.POST, consumes = {MediaType.MULTIPART_FORM_DATA_VALUE})
    public HttpEntity<byte[]> decryptFile(@RequestPart MultipartFile document) {
        var bytes = service.decryptECBFile(document);
        if (bytes == null) throw new HttpClientErrorException(HttpStatus.NOT_FOUND);
        HttpHeaders header = new HttpHeaders();
        header.setContentType(MediaType.APPLICATION_OCTET_STREAM);
        header.set(HttpHeaders.CONTENT_DISPOSITION, "attachment; filename=" + String.format("%s_%s",
                document.getName(), "decrypted.txt"));
        header.setContentLength(bytes.length);
        return new HttpEntity<byte[]>(bytes, header);
    }

}
