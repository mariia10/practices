package mariia.budiak.practices.controller;

import io.swagger.annotations.ApiParam;
import lombok.RequiredArgsConstructor;
import mariia.budiak.practices.service.CryptanalysisService;
import org.springframework.http.HttpStatus;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.client.HttpClientErrorException;

import java.util.HashMap;

@RestController
@RequestMapping("cryptanalysis/")
@RequiredArgsConstructor
public class CryptanalysisController {
    private final CryptanalysisService service;

    @RequestMapping(value = "/frequency_analysis", method = RequestMethod.GET)
    public HashMap<Character, Integer> freqAnalysis(@ApiParam(required = true) @RequestParam String phrase) {
        if (phrase == null)
            throw new HttpClientErrorException(HttpStatus.BAD_REQUEST,
                    "пожалуйста, вставте нормальный текст для зашифровки");
        return service.getFrequencyAnalysis(phrase);
    }

}
