package mariia.budiak.practices.controller;

import com.fasterxml.jackson.core.JsonProcessingException;
import io.swagger.annotations.ApiParam;
import lombok.RequiredArgsConstructor;
import mariia.budiak.practices.model.SubKey;
import mariia.budiak.practices.service.SubstitutionCipherService;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.client.HttpClientErrorException;
import org.springframework.web.client.HttpServerErrorException;

@RestController
@RequestMapping("substitution-cipher/")
@RequiredArgsConstructor
public class SubstitutionCipherController {

    private final SubstitutionCipherService service;

    @RequestMapping(value = "/uploadKey", method = RequestMethod.POST)
    public void custom(@RequestBody SubKey key) {

        service.setSubKey(key);
    }

    @RequestMapping(value = "/generateKey", method = RequestMethod.GET)
    public SubKey generate() {
        return new SubKey();
    }

    @RequestMapping(value = "/getLastKey", method = RequestMethod.GET)
    public SubKey getLastKey() {
        if (service.getSubKey() == null) {
            throw new HttpClientErrorException(HttpStatus.BAD_REQUEST,
                    "ключ не найден, необходимо загрузить ключ");
        }
        return service.getSubKey();
    }

    @RequestMapping(value = "/encode", method = RequestMethod.GET)
    public String encode(@ApiParam(required = true) @RequestParam String phrase) {
        if (phrase == null)
            throw new HttpClientErrorException(HttpStatus.BAD_REQUEST,
                    "пожалуйста, вставте нормальный текст для зашифровки");
        if (service.getSubKey() == null) {
            throw new HttpClientErrorException(HttpStatus.BAD_REQUEST,
                    "ключ не найден, необходимо загрузить ключ");
        }
        try {
            return service.encode(phrase);
        } catch (JsonProcessingException e) {
            throw new HttpServerErrorException(HttpStatus.INTERNAL_SERVER_ERROR, "ошибка сервиса");
        }
    }

    @RequestMapping(value = "/decode", method = RequestMethod.GET)
    public String decode(@ApiParam(required = true) @RequestParam String phrase) {
        if (phrase == null)
            throw new HttpClientErrorException(HttpStatus.BAD_REQUEST,
                    "пожалуйста, вставте нормальный текст для зашифровки");
        if (service.getSubKey() == null) {
            throw new HttpClientErrorException(HttpStatus.BAD_REQUEST,
                    "ключ не найден, необходимо загрузить ключ");
        }
        try {
            return service.decode(phrase);
        } catch (JsonProcessingException e) {
            throw new HttpServerErrorException(HttpStatus.INTERNAL_SERVER_ERROR, "ошибка сервиса");
        }
    }


}
