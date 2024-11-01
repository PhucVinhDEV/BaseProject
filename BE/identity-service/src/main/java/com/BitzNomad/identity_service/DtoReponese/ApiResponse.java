package com.BitzNomad.identity_service.DtoReponese;

import com.fasterxml.jackson.annotation.JsonInclude;
import lombok.*;


@Setter
@Builder
@AllArgsConstructor
@NoArgsConstructor
@JsonInclude(JsonInclude.Include.NON_NULL)
public class ApiResponse <T>{
    @Builder.Default
    private int status = 1000;
    private String message;
    private T result;
}
