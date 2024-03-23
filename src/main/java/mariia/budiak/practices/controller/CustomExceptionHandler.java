package mariia.budiak.practices.controller;

import lombok.extern.slf4j.Slf4j;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;
import org.springframework.web.client.HttpClientErrorException;
import org.springframework.web.servlet.mvc.method.annotation.ResponseEntityExceptionHandler;

@Slf4j
@RestControllerAdvice
public class CustomExceptionHandler extends ResponseEntityExceptionHandler {
    @ExceptionHandler(HttpClientErrorException.class)
    public ResponseEntity<Object> clientEx(HttpClientErrorException e) {
        log.trace("clientEx()");
        return ResponseEntity.badRequest().body(e.getMessage());
    }

}
