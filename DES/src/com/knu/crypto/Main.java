package com.knu.crypto;

import java.nio.charset.StandardCharsets;
import java.util.Random;
import java.util.Scanner;

public class Main {
    public static void main(String[] args) {
        Scanner scanner = new Scanner(System.in);
        System.out.println("write password");
        String password = scanner.nextLine();

        System.out.println("write text");
        String s = scanner.nextLine();

        byte[] array = new byte[8]; // length is bounded by 8
        new Random().nextBytes(array);
        String vectorInit = new String(array, StandardCharsets.UTF_8);

        DES d = new DES();
        System.out.println(s + "\t\tstart");

        String p = d.encrypt(s, password, vectorInit);

        System.out.println(p + "\t\tafter encrypt");

        s = d.decrypt(p, password, vectorInit);

        System.out.println(s + "\tafter decrypt");

    }
}