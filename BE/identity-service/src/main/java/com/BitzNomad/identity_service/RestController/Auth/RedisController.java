package com.BitzNomad.identity_service.RestController.Auth;

import com.BitzNomad.identity_service.Service.RedisService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.*;

import java.util.concurrent.TimeUnit;

@RestController
@RequestMapping("/redis")
public class RedisController {
    private final RedisService redisService;

    @Autowired
    public RedisController(RedisService redisService) {
        this.redisService = redisService;
    }

    @PostMapping("/set")
    public String setValue(@RequestParam String key, @RequestParam String value) {
        redisService.setValue(key, value);
        return "Value set successfully";
    }

    @PostMapping("/setWithTTL")
    public String setValueWithTTL(@RequestParam String key, @RequestParam String value, @RequestParam long timeout) {
        redisService.setValueWithTTL(key, value, timeout, TimeUnit.SECONDS);
        return "Value set with TTL successfully";
    }

    @GetMapping("/get")
    public Object getValue(@RequestParam String key) {
        return redisService.getValue(key);
    }

    @DeleteMapping("/delete")
    public String deleteValue(@RequestParam String key) {
        redisService.deleteValue(key);
        return "Value deleted successfully";
    }

    @GetMapping("/exists")
    public boolean hasKey(@RequestParam String key) {
        return redisService.hasKey(key);
    }
}
