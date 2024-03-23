package mariia.budiak.practices.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.web.servlet.config.annotation.ViewControllerRegistry;
import org.springframework.web.servlet.config.annotation.WebMvcConfigurer;
import springfox.documentation.builders.ApiInfoBuilder;
import springfox.documentation.builders.RequestHandlerSelectors;
import springfox.documentation.builders.ResponseMessageBuilder;
import springfox.documentation.schema.ModelRef;
import springfox.documentation.service.ApiInfo;
import springfox.documentation.service.ResponseMessage;
import springfox.documentation.spi.DocumentationType;
import springfox.documentation.spring.web.plugins.Docket;


@Configuration
public class SwaggerConfiguration implements WebMvcConfigurer {

    private static ResponseMessage getResponseMessage(int code, String unauthorized) {
        return new ResponseMessageBuilder().code(code)
                .message(unauthorized)
                .responseModel(new ModelRef("ErrorTransfer"))
                .build();
    }

    /**
     * Перенастраивает доступ с home page на страницу Swagger UI.
     *
     * @param registry страница
     */
    @Override
    public void addViewControllers(ViewControllerRegistry registry) {
        registry.addRedirectViewController("/swagger-ui/", "/swagger-ui.html");
    }

    /**
     * Создается Docket bean.
     *
     * @return Docket bean
     */
    @Bean
    public Docket api() {
        return new Docket(DocumentationType.SWAGGER_2).apiInfo(apiInfo())
                .select()
                .apis(RequestHandlerSelectors.basePackage("mariia.budiak.practices.controller"))
                .build();
    }

    /**
     * Заголовок и описание для swagger.
     *
     * @return страница swagger-ui.html с кастомными значениями
     */
    private ApiInfo apiInfo() {
        return new ApiInfoBuilder()
                .title("mariia's budiak practices - api")
                .build();
    }
}
