package com.vitaxa.steamauth.helper;

import java.io.*;
import java.net.URL;
import java.net.URLConnection;
import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;
import java.nio.file.*;

public final class IOHelper {
    // Charset
    public static final Charset UNICODE_CHARSET = StandardCharsets.UTF_8;

    // File options
    private static final LinkOption[] LINK_OPTIONS = {};
    private static final OpenOption[] READ_OPTIONS = {StandardOpenOption.READ};
    private static final CopyOption[] COPY_OPTIONS = {StandardCopyOption.REPLACE_EXISTING};
    private static final OpenOption[] APPEND_OPTIONS = {StandardOpenOption.CREATE, StandardOpenOption.WRITE, StandardOpenOption.APPEND};
    private static final OpenOption[] WRITE_OPTIONS = {StandardOpenOption.CREATE, StandardOpenOption.WRITE, StandardOpenOption.TRUNCATE_EXISTING};

    private IOHelper() {
    }

    public static void createParentDirs(Path path) throws IOException {
        Path parent = path.getParent();
        if (parent != null && !isDir(parent)) {
            Files.createDirectories(parent);
        }
    }

    public static void createDir(Path dir) throws IOException {
        if (!isDir(dir)) {
            Files.createDirectory(dir);
        }
    }

    public static String decode(byte[] bytes) {
        return new String(bytes, UNICODE_CHARSET);
    }

    public static byte[] encode(String s) {
        return s.getBytes(UNICODE_CHARSET);
    }

    public static boolean exists(Path path) {
        return Files.exists(path, LINK_OPTIONS);
    }

    public static boolean isDir(Path path) {
        return Files.isDirectory(path, LINK_OPTIONS);
    }


    public static boolean isEmpty(Path dir) throws IOException {
        try (DirectoryStream<Path> stream = Files.newDirectoryStream(dir)) {
            return !stream.iterator().hasNext();
        }
    }


    public static boolean isFile(Path path) {
        return Files.isRegularFile(path, LINK_OPTIONS);
    }

    public static void move(Path source, Path target) throws IOException {
        createParentDirs(target);
        Files.move(source, target, COPY_OPTIONS);
    }


    public static byte[] newBuffer() {
        return new byte[4096];
    }


    public static ByteArrayOutputStream newByteArrayOutput() {
        return new ByteArrayOutputStream();
    }


    public static char[] newCharBuffer() {
        return new char[4096];
    }

    public static InputStream newInput(URL url) throws IOException {
        URLConnection connection = url.openConnection();
        connection.setDoInput(true);
        connection.setDoOutput(false);
        return connection.getInputStream();
    }


    public static InputStream newInput(Path file) throws IOException {
        return Files.newInputStream(file, READ_OPTIONS);
    }


    public static OutputStream newOutput(Path file) throws IOException {
        return newOutput(file, false);
    }

    public static OutputStream newOutput(Path file, boolean append) throws IOException {
        createParentDirs(file);
        return Files.newOutputStream(file, append ? APPEND_OPTIONS : WRITE_OPTIONS);
    }

    public static BufferedReader newReader(InputStream input) {
        return newReader(input, UNICODE_CHARSET);
    }


    public static BufferedReader newReader(InputStream input, Charset charset) {
        return new BufferedReader(new InputStreamReader(input, charset));
    }


    public static BufferedReader newReader(URL url) throws IOException {
        return newReader(newInput(url));
    }


    public static BufferedReader newReader(Path file) throws IOException {
        return Files.newBufferedReader(file, UNICODE_CHARSET);
    }


    public static BufferedWriter newWriter(OutputStream output) {
        return new BufferedWriter(new OutputStreamWriter(output, UNICODE_CHARSET));
    }


    public static BufferedWriter newWriter(Path file) throws IOException {
        return newWriter(file, false);
    }


    public static BufferedWriter newWriter(Path file, boolean append) throws IOException {
        createParentDirs(file);
        return Files.newBufferedWriter(file, UNICODE_CHARSET, append ? APPEND_OPTIONS : WRITE_OPTIONS);
    }


    public static BufferedWriter newWriter(FileDescriptor fd) {
        return newWriter(new FileOutputStream(fd));
    }

    public static byte[] read(URL url) throws IOException {
        try (InputStream input = newInput(url)) {
            return read(input);
        }
    }

    public static void read(InputStream input, byte[] bytes) throws IOException {
        int offset = 0;
        while (offset < bytes.length) {
            int length = input.read(bytes, offset, bytes.length - offset);
            if (length < 0) {
                throw new EOFException(String.format("%d bytes remaining", bytes.length - offset));
            }
            offset += length;
        }
    }


    public static byte[] read(InputStream input) throws IOException {
        try (ByteArrayOutputStream output = newByteArrayOutput()) {
            transfer(input, output);
            return output.toByteArray();
        }
    }

    public static String read(BufferedReader reader) throws IOException {
        StringBuilder response = new StringBuilder();
        String line;
        while ((line = reader.readLine()) != null) {
            if (response.length() > 0) {
                response.append("\n");
            }
            response.append(line);
        }

        return response.toString();
    }

    public static int transfer(InputStream input, OutputStream output) throws IOException {
        int transferred = 0;
        byte[] buffer = newBuffer();
        for (int length = input.read(buffer); length >= 0; length = input.read(buffer)) {
            output.write(buffer, 0, length);
            transferred += length;
        }
        return transferred;
    }


    public static void transfer(Path file, OutputStream output) throws IOException {
        try (InputStream input = newInput(file)) {
            transfer(input, output);
        }
    }


    public static int transfer(InputStream input, Path file) throws IOException {
        return transfer(input, file, false);
    }


    public static int transfer(InputStream input, Path file, boolean append) throws IOException {
        try (OutputStream output = newOutput(file, append)) {
            return transfer(input, output);
        }
    }

    public static void write(Path file, byte[] bytes) throws IOException {
        createParentDirs(file);
        Files.write(file, bytes, WRITE_OPTIONS);
    }
}



