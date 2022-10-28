import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.FileReader;
import java.io.FileWriter;
import java.io.IOException;
import java.nio.charset.Charset;
import java.util.Scanner;

public class FEAL_NX {
	
	public static void main(String[] args) {
		Charset charset = Charset.forName("ASCII");
		Scanner in = new Scanner(System.in);
		System.out.println("Введите текст");
		String message = in.nextLine();
		while(message.isEmpty()) {
			message = in.nextLine();
		}
		System.out.println("Введите -e, если хотите зашифровать текст\n" + "-d, если хотите расшифровать текст");
		String flag = in.nextLine();
		System.out.println("Введите число раундов: ");
		int N = in.nextInt();
		while(N % 2 != 0) {
			System.out.println("Ошибка ввода, попробуйте еще раз: ");
			N = in.nextInt();
		}
		in.close();
		byte[] key = readFile("src/key.txt").getBytes(charset);
		String input = "src/plain_text.txt";
		String enc = "src/encryption.txt";
		String dec = "src/decryption.txt";
		StringBuilder sb = new StringBuilder();
		if(flag.equals("-e")) {
			writeToFile(input, message);
			byte[] plain = readFile(input).getBytes(charset);
			int size = plain.length;
			if(size % 8 != 0) {
				int c = size / 8;
				byte[] plainText = new byte[(c + 1)*8];
				System.arraycopy(plain, 0, plainText, 0, size);
				for (int i = 0; i < plainText.length/8; i++){
		        	byte[] tempText = new byte[8];
		        	System.arraycopy(plainText, i*8, tempText, 0, 8);
		            byte[] cipherText = encryption(tempText, key, N);
					for(byte aa : cipherText) {
						sb.append(String.format("%02X", aa));
					}
		        }
			} else {
				for (int i = 0; i < plain.length/8; i++){
					byte[] tempText = new byte[8];
					System.arraycopy(plain, i*8, tempText, 0, 8);
					byte[] cipherText = encryption(tempText, key, N);
					for(byte aa : cipherText) {
						sb.append(String.format("%02X", aa));
					}
				}
			}
	        writeToFile(enc, sb.toString());
	        System.out.println("\n-----------------------------------------------------");
	        System.out.println("\nВаш текст был зашифрован: ");
	        System.out.println(sb.toString());
	        sb.setLength(0);
		} else if(flag.equals("-d")) {
	        byte[] cipherText = hexStringToByteArray(readFile(enc));
	        int size = readFile(input).length();
	        for (int i = 0; i < cipherText.length/8; i++){
	        	byte[] tempText = new byte[8];
	        	System.arraycopy(cipherText, i*8, tempText, 0, 8);
	        	byte[] decryptedText = decryption(tempText, key, N);
	        	if(i == cipherText.length/8 - 1) {
		        	if(size % 8 == 0) {
		        		String str1 = new String(decryptedText, charset);
		                sb.append(str1);
		        	}else {
		        		String str1 = new String(decryptedText, charset);
		        		char[] arr = new char[size % 8]; 
		        		str1.getChars(0, size % 8, arr, 0);
		        		for(int j = 0; j < arr.length; j++) {
		        			sb.append(arr[j]);
		        		}
		        	}
		        	break;
	        	}
	        	String str = new String(decryptedText, charset);
	            sb.append(str);
	        }
	        writeToFile(dec, sb.toString());
	        System.out.println("\n-----------------------------------------------------");
	        System.out.println("\nВаш текст был расшифрован: ");
	        System.out.println(sb.toString());
	        sb.setLength(0);
		} 
	}
	
	public static byte[] encryption(byte[] plainText, byte[] key, int N) {
		if(plainText.length == 8 && key.length == 16 && N >= 0) {
			byte[][] subKeys = keyGeneration(key, N);
			byte[] firstXOR = {subKeys[N][0],
							   subKeys[N][1],
							   subKeys[N+1][0],
							   subKeys[N+1][1],
							   subKeys[N+2][0],
							   subKeys[N+2][1],
							   subKeys[N+3][0],
							   subKeys[N+3][1]};
			plainText = XOR(plainText, firstXOR); // (L0, R0 ) = (L0, R0 ) ⊕ (KN, KN+1, KN+2, KN+3 )
			// Plaintext P is separated into LN and RN of equal lengths (32 bits), i.e., (LN,RN)=P
			byte[] L0 = new byte[4];
			System.arraycopy(plainText, 0, L0, 0, 4);
			byte[] R0 = new byte[4];
			System.arraycopy(plainText, 4, R0, 0, 4);
			R0 = XOR(L0, R0); // (L0, R0 )= (L0, R0 ) ⊕ ( φ , L0 )
			//Core Loop
			for(int i = 0; i < N; i++) {
				L0 = XOR(L0, F(R0,subKeys[i])); // Rr = Lr-1 ⊕ f (Rr-1, Kr-1)
				byte[] temp = new byte[4];
				System.arraycopy(L0, 0, temp, 0, 4); // Lr = Rr-1
				System.arraycopy(R0, 0, L0, 0, 4);
				System.arraycopy(temp, 0, R0, 0, 4);
			}
			
			byte[] cipherText = new byte[8];
			byte[] lastXOR = {subKeys[N+4][0],
							  subKeys[N+4][1],
							  subKeys[N+5][0],
							  subKeys[N+5][1],
							  subKeys[N+6][0],
							  subKeys[N+6][1],
							  subKeys[N+7][0],
							  subKeys[N+7][1]};
			L0 = XOR(L0, R0); // (RN , LN)= (RN , LN) ⊕ ( φ , RN) 
			System.arraycopy(R0, 0, cipherText, 0, 4);
			System.arraycopy(L0, 0, cipherText, 4, 4);
			cipherText = XOR(cipherText, lastXOR); // (RN , LN)= (RN, LN) ⊕ (KN+4, KN+5, KN+6, KN+7)
			return cipherText;
		} else {
			throw new IllegalArgumentException();
		}
	}
	
	public static byte[] decryption(byte[] cipherText, byte[] key, int N) {
		if(cipherText.length == 8 && key.length == 16 && N >= 0) {
			byte[][] subKeys = keyGeneration(key, N);
			byte[] firstXOR = {subKeys[N+4][0],
							   subKeys[N+4][1],
							   subKeys[N+5][0],
							   subKeys[N+5][1],
							   subKeys[N+6][0],
							   subKeys[N+6][1],
							   subKeys[N+7][0],
							   subKeys[N+7][1]};
			cipherText = XOR(cipherText, firstXOR); // (RN , LN)= (RN, LN) ⊕ (KN+4, KN+5, KN+6, KN+7)
			// Ciphertext (RN, LN) is separated into RN and LN of equal lengths.
			byte[] LN = new byte[4];
			System.arraycopy(cipherText, 4, LN, 0, 4);
			byte[] RN = new byte[4];
			System.arraycopy(cipherText, 0, RN, 0, 4);
			LN = XOR(LN, RN); //(RN , LN)= (RN, LN) ⊕ ( φ , RN)
			for(int i = N-1; i >= 0; i--) {
				byte[] temp = new byte[4];
				System.arraycopy(LN, 0, temp, 0, 4); // Rr-1 = Lr
				System.arraycopy(RN, 0, LN, 0, 4);
				System.arraycopy(temp, 0, RN, 0, 4);
				LN = XOR(LN, F(RN,subKeys[i])); // Lr-1 = Rr ⊕ f (Lr, Kr-1)
			}
			
			byte[] plainText = new byte[8];
			byte[] lastXOR = {subKeys[N][0],
							  subKeys[N][1],
							  subKeys[N+1][0],
							  subKeys[N+1][1],
							  subKeys[N+2][0],
							  subKeys[N+2][1],
							  subKeys[N+3][0],
							  subKeys[N+3][1]};
			RN = XOR(LN, RN); //(L0 , R0)= (L0, R0) ⊕ ( φ , L0)
			System.arraycopy(LN, 0, plainText, 0, 4);
			System.arraycopy(RN, 0, plainText, 4, 4);
			plainText = XOR(plainText, lastXOR); // (L0, R0)= (L0, R0) ⊕ (KN, KN+1, KN+2, KN+3)
			return plainText;
		} else {
			throw new IllegalArgumentException();
		}
	}
	
	public static byte[][] keyGeneration(byte[] Key, int N) {
		if(Key.length == 16) {
			// Initialization
			byte[][] subKeys = new byte[N+8][2];
			// Input 128-bit key is equally divided into a 64-bit left key, KL, and a 64-bit 
			// right key, KR. (KL, KR) is the inputted 128-bit key.
			byte[] A0 = new byte[4]; // the left half of KL
			System.arraycopy(Key, 0, A0, 0, 4);
			byte[] B0 = new byte[4]; // the right half of KL
			System.arraycopy(Key, 4, B0, 0, 4);
			byte[] KR1 = new byte[4]; // the left half of KR
			System.arraycopy(Key, 8, KR1, 0, 4);
			byte[] KR2 = new byte[4]; // the right half of KR
			System.arraycopy(Key, 12, KR2, 0, 4);
			byte[] Dr = new byte[4]; 
			byte[] Qr = new byte[4]; // temporary variable
			byte[] KRX = XOR(KR1,KR2);
	        // Qr = KR1 ⊕ KR2 for r = 1, 4, 7..., (r = 3i+1; i = 0, 1, ...)
	        // Qr = KR1 for r = 2, 5, 8..., (r = 3i+2; i = 0, 1, ...)
	        // Qr = KR2 for r = 3, 6, 9..., (r = 3i+3; i = 0, 1, ...)
	        // where 1 ≦ r ≦ (N/2)+4, (N ≧ 32, N: even).
			for(int i = 0; i < 4 + (N/2); i++) {
				if(i%3 == 0) {
					Qr = XOR(B0, KRX);
				} else if(i%3 == 1) {
					Qr = XOR(B0, KR1);
				} else {
					Qr = XOR(B0, KR2);
				}
				if(i > 0) {
					Qr = XOR(Qr, Dr);
				}
				
				System.arraycopy(A0, 0, Dr, 0, 4); // Dr = Ar-1 
				A0 = Fk(A0, Qr); // Br = fK(α, β) = fK (Ar-1, (Br-1 ⊕ Dr-1) ⊕ Qr))        
				System.arraycopy(A0, 0, subKeys[2*i], 0, 2); // K2(r-1) = (Br0, Br1)
				System.arraycopy(A0, 2, subKeys[(2*i)+1], 0, 2); // K2(r-1)+1 = (Br2, Br3)
				byte[] temp = new byte[4]; // Ar = Br-1
				System.arraycopy(A0, 0, temp, 0, 4);
				System.arraycopy(B0, 0, A0, 0, 4);
				System.arraycopy(temp, 0, B0, 0, 4);
			}
			return subKeys;
		} else {
			throw new IllegalArgumentException();
		}
	}
	// α = (α0 , α1, α2, α3), β = ( β0, β1).
	// (f0, f1, f2, f3) = f are calculated in sequence.
	// f1 =α1 ⊕ β0
	// f2 =α2 ⊕ β1
	// f1 = f1 ⊕ α0
	// f2 = f2 ⊕ α3
	// f1 = S1 (f1, f2 )
	// f2 = S0 (f2, f1 )
	// f0 = S0 (α0, f1)
	// f3 = S1 (α3, f2 )
	public static byte[] F(byte[] a, byte[] b) {
		if(a.length == 4 && b.length == 2) {
			byte f1 = (byte)(a[1]^b[0]);
	        byte f2 = (byte)(a[2]^b[1]);
	        f1 = (byte)(f1^a[0]);
	        f2 = (byte)(f2^a[3]);
	        f1 = S(f1, f2, (byte) 1);
	        f2 = S(f2, f1, (byte) 0);
	        byte f0 = S(a[0], f1, (byte) 0);
	        byte f3 = S(a[3], f2, (byte) 1);
	        byte[] f = {f0,f1,f2,f3};
	        return f;
		} else {
			throw new IllegalArgumentException();
		}
	}
	// α = (α0, α1, α2, α3), β = ( β0, β1, β2, β3).
	// (fK0, fK1, fK2, fK3) = fK are calculated in sequence.
	// fK1 = α1 ⊕ α0
	// fK2 = α2 ⊕ α3
	// fK1 = S1 (fK1, ( fK2 ⊕ β0 ) )
	// fK2 = S0 (fK2, ( fK1 ⊕ β1 ) )
	// fK0 = S0 (α0, ( fK1 ⊕ β2 ) )
	// fK3 = S1 (α3, ( fK2 ⊕ β3 ) )
	public static byte[] Fk(byte[] a, byte[] b) {																					
		if(a.length == 4 && b.length == 4) {
			byte fk1 = (byte)(a[1]^a[0]);
	        byte fk2 = (byte)(a[2]^a[3]);
	        fk1 = S(fk1, (byte)(fk2^b[0]), (byte) 1);
	        fk2 = S(fk2, (byte)(fk1^b[1]), (byte) 0);
	        byte fk0 = S(a[0], (byte)(fk1^b[2]), (byte)0);
	        byte fk3 = S(a[3], (byte)(fk2^b[3]), (byte)1);
	        byte[] fK = {fk0, fk1, fk2, fk3};
	        return fK;
		} else {
			throw new IllegalArgumentException();
		}
	}
	
	// S0(X1, X2)=Rot2((X1 + X2) mod 256) when D == 0
	// S1(X1, X2)=Rot2((X1 + X2 + 1) mod 256) when D == 1 
	public static byte S(byte A, byte B, byte D) {
		if(D == 0 || D == 1) {
			byte t = (byte)((A + B + D)%256);
	        return leftRotation(t,2);
	    } else {
	        throw new IllegalArgumentException();
	    }
	}
	
	public static byte[] XOR(byte[] a, byte[] b) {
		if(a.length == b.length) {
			byte[] result = new byte[a.length];
			for(int i = 0; i < a.length; i++) {
				result[i] = (byte)(a[i]^b[i]);
			}
			return result;
		} else {
			throw new IllegalArgumentException();
		}
	}
	
	public static byte leftRotation(byte bits, int shift) {
		return (byte)((bits << shift) | (bits >>> (8 - shift)));
	}
	
	public static byte[] hexStringToByteArray(String s) {
	    int len = s.length();
	    byte[] data = new byte[len / 2];
	    for (int i = 0; i < len; i += 2) {
	        data[i / 2] = (byte)((Character.digit(s.charAt(i), 16) << 4) + Character.digit(s.charAt(i+1), 16));
	    }
	    return data;
	}
	
	public static String readFile(String filename) {
		try (BufferedReader br = new BufferedReader(new FileReader(filename))) {
			StringBuilder sb = new StringBuilder();
		    String currentLine;
		    while ((currentLine = br.readLine()) != null) {
		    	sb.append(currentLine);
		    }
		    String plaintext = sb.toString();
		    return plaintext;
		}
		catch (IOException e){
			System.out.print("\nInput file with this name was not found.");
		    return null;
		}
	}

	public static void writeToFile(String filename, String str) {
		try (BufferedWriter writer = new BufferedWriter(new FileWriter(filename))) {
			writer.write(str);
			writer.close();
		}
		catch (IOException ioe) {
			System.out.println("\nFailed to create cipher text file.");
		}
	}
	
	
}