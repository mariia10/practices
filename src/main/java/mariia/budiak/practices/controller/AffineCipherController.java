package mariia.budiak.practices.controller;

import io.swagger.annotations.ApiParam;
import lombok.RequiredArgsConstructor;
import mariia.budiak.practices.model.AffineKey;
import mariia.budiak.practices.service.AffineCipherService;
import org.springframework.http.HttpStatus;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.client.HttpClientErrorException;

@RestController
@RequestMapping("affine-cipher/")
@RequiredArgsConstructor
public class AffineCipherController {
    private final AffineCipherService service;

    @RequestMapping(value = "/uploadKey", method = RequestMethod.POST)
    public void custom(@RequestBody AffineKey key) {
        service.setAffineKey(key);
    }

    @RequestMapping(value = "/encode", method = RequestMethod.GET)
    public String encode(@ApiParam(required = true) @RequestParam String phrase) {
        if (phrase == null)
            throw new HttpClientErrorException(HttpStatus.BAD_REQUEST,
                    "пожалуйста, вставте нормальный текст для зашифровки");
        if (service.getAffineKey().getAlpha() == null) {
            throw new HttpClientErrorException(HttpStatus.BAD_REQUEST,
                    "ключ не найден, необходимо загрузить ключ");
        }
        return service.encode(phrase);
    }

    @RequestMapping(value = "/decode", method = RequestMethod.GET)
    public String decode(@ApiParam(required = true) @RequestParam String phrase) {
        if (phrase == null)
            throw new HttpClientErrorException(HttpStatus.BAD_REQUEST,
                    "пожалуйста, вставте нормальный текст для зашифровки");
        if (service.getAffineKey().getAlpha() == null) {
            throw new HttpClientErrorException(HttpStatus.BAD_REQUEST,
                    "ключ не найден, необходимо загрузить ключ");
        }

        return service.decode(phrase);

    }

}
