package com.vitaxa.steamauth.helper;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.ObjectWriter;

import java.io.IOException;
import java.io.Reader;
import java.util.Map;

public class Json {

    private static final Json DEFAULT_SERIALIZER;

    static {
        DEFAULT_SERIALIZER = new Json(new ObjectMapper());
    }

    private final ObjectMapper mapper;
    private final ObjectWriter writer;
    private final ObjectWriter prettyWriter;

    private Json(ObjectMapper mapper) {
        this.mapper = mapper;
        this.writer = mapper.writer();
        this.prettyWriter = mapper.writerWithDefaultPrettyPrinter();
    }

    public ObjectMapper mapper() {
        return mapper;
    }

    public ObjectWriter writer() {
        return writer;
    }

    public ObjectWriter prettyWriter() {
        return prettyWriter;
    }

    public static Json getInstance() {
        return DEFAULT_SERIALIZER;
    }

    public <T> T fromJson(byte[] bytes, TypeReference<T> typeRef) {
        try {
            return mapper.readValue(bytes, typeRef);
        } catch (IOException e) {
            throw new JsonException(e);
        }
    }

    public <T> T fromJson(byte[] bytes, Class<T> valueType) {
        try {
            return mapper.readValue(bytes, valueType);
        } catch (IOException e) {
            throw new JsonException(e);
        }
    }

    public <T> T fromJson(String json, TypeReference<T> typeRef) {
        try {
            return mapper.readValue(json, typeRef);
        } catch (IOException e) {
            throw new JsonException(e);
        }
    }

    public <T> T fromJson(String json, Class<T> valueType) {
        try {
            return mapper.readValue(json, valueType);
        } catch (IOException e) {
            throw new JsonException(e);
        }
    }

    public <T> T fromJson(Reader reader, Class<T> valueType) {
        try {
            return mapper.readValue(reader, valueType);
        } catch (IOException e) {
            throw new JsonException(e);
        }
    }

    public Map<String, Object> mapFromJson(byte[] bytes) {
        try {
            return mapper.readValue(bytes, new TypeReference<Map<String, Object>>() {
            });
        } catch (IOException e) {
            throw new JsonException(e);
        }
    }

    public Map<String, Object> mapFromJson(String json) {
        try {
            return mapper.readValue(json, new TypeReference<Map<String, Object>>() {
            });
        } catch (IOException e) {
            throw new JsonException(e);
        }
    }

    public JsonNode nodeFromJson(String json) {
        try {
            return mapper.readTree(json);
        } catch (IOException e) {
            throw new JsonException(e);
        }
    }

    public JsonNode nodeFromObject(Object obj) {
        try {
            return mapper.readTree(toString(obj));
        } catch (IOException e) {
            throw new JsonException(e);
        }
    }

    public <T> String toJson(T json) {
        try {
            return mapper.writeValueAsString(json);
        } catch (JsonProcessingException e) {
            throw new JsonException(e);
        }
    }

    public <T> byte[] toJsonByte(T json) {
        try {
            return mapper.writeValueAsBytes(json);
        } catch (JsonProcessingException e) {
            throw new JsonException(e);
        }
    }

    public String toString(Object obj) {
        try {
            return writer.writeValueAsString(obj);
        } catch (IOException e) {
            throw new JsonException(e);
        }
    }

    public String toPrettyString(Object obj) {
        try {
            return prettyWriter.writeValueAsString(obj);
        } catch (IOException e) {
            throw new JsonException(e);
        }
    }

    public byte[] toByteArray(Object obj) {
        try {
            return prettyWriter.writeValueAsBytes(obj);
        } catch (IOException e) {
            throw new JsonException(e);
        }
    }

    public static class JsonException extends RuntimeException {
        private JsonException(Exception ex) {
            super(ex);
        }
    }
}
