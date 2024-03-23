package mariia.budiak.practices.controller;

import io.swagger.annotations.ApiParam;
import lombok.RequiredArgsConstructor;
import mariia.budiak.practices.model.AffineRecursiveKeys;
import mariia.budiak.practices.service.AffineRecursiveCipherService;
import org.springframework.http.HttpStatus;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.client.HttpClientErrorException;

@RestController
@RequestMapping("affine-recursive-cipher/")
@RequiredArgsConstructor
public class AffineRecursiveCipherController {
    private final AffineRecursiveCipherService service;

    @RequestMapping(value = "/uploadKeys", method = RequestMethod.POST)
    public void custom(@RequestBody AffineRecursiveKeys keys) {
        service.setSubKeys(keys);
    }

    @RequestMapping(value = "/encode", method = RequestMethod.GET)
    public String encode(@ApiParam(required = true) @RequestParam String phrase) {
        if (phrase == null)
            throw new HttpClientErrorException(HttpStatus.BAD_REQUEST,
                    "пожалуйста, вставте нормальный текст для зашифровки");
        if (service.getKeys().getAffineKeyHashMap().isEmpty()) {
            throw new HttpClientErrorException(HttpStatus.BAD_REQUEST,
                    "ключ не найден, необходимо загрузить ключи");
        }
        return service.encode(phrase);
    }

    @RequestMapping(value = "/decode", method = RequestMethod.GET)
    public String decode(@ApiParam(required = true) @RequestParam String phrase) {
        if (phrase == null)
            throw new HttpClientErrorException(HttpStatus.BAD_REQUEST,
                    "пожалуйста, вставте нормальный текст для зашифровки");
        if (service.getKeys().getAffineKeyHashMap().isEmpty()) {
            throw new HttpClientErrorException(HttpStatus.BAD_REQUEST,
                    "ключ не найден, необходимо загрузить ключи");
        }

        return service.decode(phrase);

    }

}
