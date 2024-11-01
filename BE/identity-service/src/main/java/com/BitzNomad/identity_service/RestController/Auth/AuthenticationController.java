package com.BitzNomad.identity_service.RestController.Auth;

import com.BitzNomad.identity_service.DtoReponese.ApiResponse;
import com.BitzNomad.identity_service.DtoReponese.AuthenticationResponse;
import com.BitzNomad.identity_service.DtoReponese.IntrospecResponsee;
import com.BitzNomad.identity_service.DtoRequest.*;
import com.BitzNomad.identity_service.Exception.AppException;
import com.BitzNomad.identity_service.Exception.ErrorCode;
import com.BitzNomad.identity_service.Service.AuthenticationService;
import com.BitzNomad.identity_service.Service.AuthenticationService2;
import com.BitzNomad.identity_service.Service.MailerService;
import com.BitzNomad.identity_service.Service.UserService;
import com.BitzNomad.identity_service.entity.Auth.User;
import com.nimbusds.jose.JOSEException;
import jakarta.mail.MessagingException;
import lombok.AccessLevel;
import lombok.RequiredArgsConstructor;
import lombok.experimental.FieldDefaults;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.*;

import java.text.ParseException;
import java.util.Random;

@RestController
@RequestMapping("/auth")
@FieldDefaults(level =  AccessLevel.PRIVATE )
public class AuthenticationController {


    @Autowired
    AuthenticationService2 authenticationService;

    @Autowired
    UserService userService;

    @Autowired
    MailerService mailerService;


    @PostMapping("/login")
    @CrossOrigin
    ApiResponse<AuthenticationResponse>  authenticate(@RequestBody AuthenticationRequest request) {

        AuthenticationResponse result = authenticationService.authenticate(request);
        return  ApiResponse.<AuthenticationResponse>builder()
                .result(result)
                .build();
    }

//    @PostMapping("/outbound/authentication")
//    ApiResponse<AuthenticationResponse> outboundAuthenticate(@RequestParam("code") String code) {
//        var result = authenticationService.outboundAuthenticate(code);
//        return ApiResponse.<AuthenticationResponse>builder().result(result).build();
//    }

    @PostMapping("/refesh")
    ApiResponse<AuthenticationResponse>  authenticate(@RequestBody RefeshRequest request) throws ParseException, JOSEException {
        AuthenticationResponse result = authenticationService.refreshToken(request);
        return  ApiResponse.<AuthenticationResponse>builder()
                .result(result)
                .build();
    }

    @PostMapping("/logout")
    ApiResponse<Void>  logout(@RequestBody LogoutRequest request) throws ParseException, JOSEException {

        authenticationService.logout(request);
        return  ApiResponse.<Void>builder()
                .build();
    }
    @PostMapping("/instrospec")
    ApiResponse<IntrospecResponsee>  authenticate(@RequestBody IntrospecRequest request) throws ParseException, JOSEException {

        IntrospecResponsee result = authenticationService.introspect(request);
        return  ApiResponse.<IntrospecResponsee>builder()
                .status(201)
                .result(result)
                .build();
    }


    @PostMapping(value = "/api/send-verify")
    public ApiResponse<Integer> sendverify(@RequestParam("Email") String Email) {
        Random random = new Random();
        int min = 100000;
        int max = 999999;
        int verificationCode = random.nextInt(max - min + 1) + min;
        User user = userService.getUserById(Email);
        if( userService.existsByUsername(Email)){
            MailInfo mailSend = new MailInfo();
            mailSend.setFrom("artdevk18@gmail.com");
            mailSend.setTo(Email);
            mailSend.setSubject("Verification Code for Password Change");
            mailSend.setBody(formatEmailBody(verificationCode,user));
            try {
                mailerService.send(mailSend);
                return ApiResponse.<Integer>builder()
                        .message("send Verifi Code Successfully")
                        .result(verificationCode)
                        .build();
            } catch (MessagingException e) {
                throw new RuntimeException(e.getMessage());
            }
        }
        else{
            throw  new AppException(ErrorCode.UserExitsted);
        }

    }

    private String formatEmailBody(int verificationCode,User user) {
        return "<html>" +
                "<body>" +
                "<h2>Your Verification Code</h2>" +
                "<p>Dear "+user.getLastName()+",</p>" +
                "<p>Your verification code for password change is:</p>" +
                "<h3>" + verificationCode + "</h3>" +
                "<p>Please use this code to verify your email address.</p>" +
                "<br>" +
                "<p>Best regards,</p>" +
                "<p>WareHouse Company Name</p>" +
                "</body>" +
                "</html>";
    }
}
