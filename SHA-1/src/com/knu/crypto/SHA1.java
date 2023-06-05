import java.util.Scanner;

// This class implements the SHA-1 hashing algorithm
public class SHA1 {
    // Length of the message
    public static int messLength = 0;

    // Main method to get the input from the user
    public static void main(String[] args) {
        // Prompt the user to enter the text to be encrypted
        System.out.println("Enter Text to be encypted:");
        Scanner sc = new Scanner(System.in);
        String word = sc.nextLine();
        System.out.println("Plain Text: " + word);

        // Convert the entered word to binary
        String binary = convertToBinary(word);
        messLength = binary.length();
        // Calculate modulus of the word
        calculateMod(word, binary);
    }

    // Method to convert a string to binary
    public static String convertToBinary(String word) {
        byte[] bytes = word.getBytes();
        StringBuilder binary = new StringBuilder();

        // Convert each byte to binary
        for (byte b : bytes) {
            int val = b;
            for (int i = 0; i < 8; i++) {
                binary.append((val & 128) == 0 ? 0 : 1);
                val <<= 1;
            }
            binary.append(' ');
        }

        return binary.toString();
    }

    // Method to calculate modulus
    public static void calculateMod(String word, String binary) {
        int binaryMessageLength = word.length() * 8 - 8;
        String endBitLength = calculateMessageLength(binaryMessageLength+8);
        int subMod = endBitLength.length();
        int temp = (binaryMessageLength) % 512;

        if (432 - temp < 0) {
            int x = 512 - temp;
            temp = x + 440 + temp + 64;
        } else {
            temp = 432 - temp;
        }

        int binaryZeros = temp;
        String onePadded = "10000000";
        binary = binary.replaceAll("\\s+", "");
        createMessageLength(binary, onePadded, binaryZeros, endBitLength);
    }

    // Method to calculate message length
    public static String calculateMessageLength(int bitLength) {
        String tempBitsLength = Integer.toBinaryString(bitLength);
        StringBuilder sb = new StringBuilder(tempBitsLength);
        int temp = 64 - tempBitsLength.length();

        // Fill up the length to 64 bits
        while (temp > 0) {
            sb.insert(0, 0);
            temp--;
        }

        return sb.toString();
    }

    // Method to create complete message
    public static String createMessageLength(String message, String paddedOne, int zeros, String endLength) {
        StringBuilder messageBinary = new StringBuilder(message);
        messageBinary.insert(messageBinary.toString().length(), paddedOne);

        // Add zeros to the message
        while (zeros > 0) {
            messageBinary.insert(messageBinary.toString().length(), 0);
            zeros--;
        }

        // Add the end length to the message
        messageBinary.insert(messageBinary.toString().length(), endLength);
        String m = printMessage(messageBinary.toString());
        m = m.replaceAll("\\s+", "");
        int[] mArray = new int[m.toString().length()/32];

        // Convert the message to an array of integers
        for (int i = 0; i < m.toString().length(); i+=32) {
            mArray[i/32] = Integer.valueOf(m.substring(i+1, i+32),2);
            if(m.charAt(i) == '1'){
                mArray[i/32] |= 0X80000000;
            }
            // Print the decimal, binary, and hex values of the input
            System.out.printf("Decimal(iterator), String(Binary), Hex values of input: %d %s %x\n", i, m.substring(i, i+32),mArray[i/32]);
        }

        // Calculate the hash of the message
        hash(mArray);
        return messageBinary.toString();
    }

    // Method to print the message in a formatted way
    public static String printMessage(String message) {
        StringBuilder sb = new StringBuilder(message);
        int num = message.length();

        // Insert spaces every 32 bits for readability
        while (num > 0) {
            if (num % 32 == 0) {
                sb.insert(num, " ");
            }
            num--;
        }

        return sb.toString();
    }

    // Function for left rotating an integer x by shift number of bits
    private static int leftrotate(int x, int shift) {
        return ((x << shift) | (x >>> (32 - shift)));
    }

    // Constants for the SHA-1 algorithm
    private static int h1 = 0x67452301;
    private static int h2 = 0xEFCDAB89;
    private static int h3 = 0x98BADCFE;
    private static int h4 = 0x10325476;
    private static int h5 = 0xC3D2E1F0;
    private static int k1 = 0x5A827999;
    private static int k2 = 0x6ED9EBA1;
    private static int k3 = 0x8F1BBCDC;
    private static int k4 = 0xCA62C1D6;

    // Method to calculate the SHA-1 hash
    private static String hash(int[] z) {
        int integer_count = z.length;
        int[] intArray = new int[80];
        int j = 0;

        // Extend the sixteen 32-bit words into eighty 32-bit words
        for(int i = 0; i < integer_count; i += 16) {
            for(j = 0; j <= 15; j++)
                intArray[j] = z[j+i];
            for ( j = 16; j <= 79; j++ ) {
                intArray[j] = leftrotate(intArray[j - 3] ^ intArray[j - 8] ^ intArray[j - 14] ^ intArray[j - 16], 1);
            }

            // Initialize variables for the main loop
            int A = h1;
            int B = h2;
            int C = h3;
            int D = h4;
            int E = h5;
            int t = 0; //temp

            // Main loop of the SHA-1 algorithm
            for ( int x = 0; x <= 19; x++ ) {
                t = leftrotate(A,5)+((B&C)|((~B)&D))+E+intArray[x]+k1;
                E=D; D=C; C=leftrotate(B,30); B=A; A=t;
            }
            for ( int b = 20; b <= 39; b++ ) {
                t = leftrotate(A,5)+(B^C^D)+E+intArray[b]+k2;
                E=D; D=C; C=leftrotate(B,30); B=A; A=t;
            }
            for (int c = 40;
            c <= 59; c++ ) {
                t = leftrotate(A,5)+((B&C)|(B&D)|(C&D))+E+intArray[c]+k3;
                E=D; D=C; C=leftrotate(B,30); B=A; A=t;
            }
            for ( int d = 60; d <= 79; d++ ) {
                t = leftrotate(A,5)+(B^C^D)+E+intArray[d]+k4;
                E=D; D=C; C=leftrotate(B,30); B=A; A=t;
            }

            // Add the hash of this block to the total
            h1+=A; h2+=B; h3+=C; h4+=D; h5+=E;

        }

        // Convert the hashes to hex strings
        String h1Length = Integer.toHexString(h1);
        String h2Length = Integer.toHexString(h2);
        String h3Length = Integer.toHexString(h3);
        String h4Length = Integer.toHexString(h4);
        String h5Length = Integer.toHexString(h5);

        // If the hex strings are too short, prepend them with zeros
        if(h1Length.length() < 8) {
            StringBuilder h1L = new StringBuilder(h1Length);
            h1L.insert(0,0);
            h1Length = h1L.toString();
        } else if(h2Length.length() < 8) {
            StringBuilder h2L = new StringBuilder(h2Length);
            h2L.insert(0,0);
            h2Length = h2L.toString();
        } else if(h3Length.length() < 8) {
            StringBuilder h3L = new StringBuilder(h3Length);
            h3L.insert(0,0);
            h3Length = h3L.toString();
        } else if(h4Length.length() < 8) {
            StringBuilder h4L = new StringBuilder(h4Length);
            h4L.insert(0,0);
            h4Length = h4L.toString();
        } else if(h5Length.length() < 8) {
            StringBuilder h5L = new StringBuilder(h5Length);
            h5L.insert(0,0);
            h5Length = h5L.toString();
        }

        // Concatenate the hashes to form the final hash
        String hh = h1Length + h2Length + h3Length + h4Length + h5Length;
        // Print the final hash
        System.out.println("Result: " + hh);

        // Return null because the method doesn't need to return anything
        return null;
    }
}
