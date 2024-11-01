package com.BitzNomad.identity_service.Service;

import io.swagger.v3.oas.annotations.security.SecurityRequirement;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.stereotype.Service;

import java.util.concurrent.TimeUnit;

@Service
@SecurityRequirement(name = "bearer-key")
public class RedisService {
    private final RedisTemplate<String, Object> redisTemplate;

    @Autowired
    public RedisService(RedisTemplate<String, Object> redisTemplate) {
        this.redisTemplate = redisTemplate;
    }

    // Lưu giá trị với một key vào Redis
    public void setValue(String key, Object value) {
        redisTemplate.opsForValue().set(key, value);
    }

    // Lưu giá trị với thời gian sống (TTL)
    public void setValueWithTTL(String key, Object value, long timeout, TimeUnit unit) {
        redisTemplate.opsForValue().set(key, value, timeout, unit);
    }

    // Lấy giá trị từ Redis theo key
    public Object getValue(String key) {
        return redisTemplate.opsForValue().get(key);
    }

    // Xóa giá trị từ Redis theo key
    public void deleteValue(String key) {
        redisTemplate.delete(key);
    }

    // Kiểm tra xem một key có tồn tại trong Redis không
    public boolean hasKey(String key) {
        return Boolean.TRUE.equals(redisTemplate.hasKey(key));
    }
}
