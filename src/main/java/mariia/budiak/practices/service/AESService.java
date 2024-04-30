package mariia.budiak.practices.service;

import org.apache.tomcat.util.http.fileupload.IOUtils;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Service;
import org.springframework.web.client.HttpServerErrorException;
import org.springframework.web.multipart.MultipartFile;

import java.io.*;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.Base64;
import java.util.Scanner;

import static java.lang.System.in;

@Service
public class AESService {
    /**
     * The round constant word array
     * Константа раунда — это слово,
     * в котором три крайних правых байта всегда равны 0. Таким образом, эффект XOR слова с Rcon заключается в выполнении XOR только для самого левого байта слова
     */

    protected static final int[] rCon = {
            0x01000000, 0x02000000, 0x04000000,
            0x08000000,
            0x10000000, 0x20000000, 0x40000000,
            0x80000000,
            0x1b000000, 0x36000000, 0x6c000000};
    /**
     * Матрица sbox
     * Таблица нелинейных замен, используемая в нескольких преобразованиях байтовых замен и в процедуре расширения ключа для выполнения замены байтового значения один к одному
     */
    private static final int[] sBox = new int[]{
            0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
            0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
            0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
            0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
            0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
            0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
            0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
            0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
            0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
            0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
            0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
            0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
            0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
            0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
            0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
            0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16};
    /**
     * Матрица rsBox (для дешифрования)
     * Это получается применением обратного аффинного выражения
     * преобразованиес последующим нахождением мультипликативной инферсии  в GF(2^8)
     */
    private static final int[] rsBox = new int[]{
            0x52, 0x09, 0x6a, 0xd5, 0x30, 0x36, 0xa5, 0x38, 0xbf, 0x40, 0xa3, 0x9e, 0x81, 0xf3, 0xd7, 0xfb,
            0x7c, 0xe3, 0x39, 0x82, 0x9b, 0x2f, 0xff, 0x87, 0x34, 0x8e, 0x43, 0x44, 0xc4, 0xde, 0xe9, 0xcb,
            0x54, 0x7b, 0x94, 0x32, 0xa6, 0xc2, 0x23, 0x3d, 0xee, 0x4c, 0x95, 0x0b, 0x42, 0xfa, 0xc3, 0x4e,
            0x08, 0x2e, 0xa1, 0x66, 0x28, 0xd9, 0x24, 0xb2, 0x76, 0x5b, 0xa2, 0x49, 0x6d, 0x8b, 0xd1, 0x25,
            0x72, 0xf8, 0xf6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xd4, 0xa4, 0x5c, 0xcc, 0x5d, 0x65, 0xb6, 0x92,
            0x6c, 0x70, 0x48, 0x50, 0xfd, 0xed, 0xb9, 0xda, 0x5e, 0x15, 0x46, 0x57, 0xa7, 0x8d, 0x9d, 0x84,
            0x90, 0xd8, 0xab, 0x00, 0x8c, 0xbc, 0xd3, 0x0a, 0xf7, 0xe4, 0x58, 0x05, 0xb8, 0xb3, 0x45, 0x06,
            0xd0, 0x2c, 0x1e, 0x8f, 0xca, 0x3f, 0x0f, 0x02, 0xc1, 0xaf, 0xbd, 0x03, 0x01, 0x13, 0x8a, 0x6b,
            0x3a, 0x91, 0x11, 0x41, 0x4f, 0x67, 0xdc, 0xea, 0x97, 0xf2, 0xcf, 0xce, 0xf0, 0xb4, 0xe6, 0x73,
            0x96, 0xac, 0x74, 0x22, 0xe7, 0xad, 0x35, 0x85, 0xe2, 0xf9, 0x37, 0xe8, 0x1c, 0x75, 0xdf, 0x6e,
            0x47, 0xf1, 0x1a, 0x71, 0x1d, 0x29, 0xc5, 0x89, 0x6f, 0xb7, 0x62, 0x0e, 0xaa, 0x18, 0xbe, 0x1b,
            0xfc, 0x56, 0x3e, 0x4b, 0xc6, 0xd2, 0x79, 0x20, 0x9a, 0xdb, 0xc0, 0xfe, 0x78, 0xcd, 0x5a, 0xf4,
            0x1f, 0xdd, 0xa8, 0x33, 0x88, 0x07, 0xc7, 0x31, 0xb1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xec, 0x5f,
            0x60, 0x51, 0x7f, 0xa9, 0x19, 0xb5, 0x4a, 0x0d, 0x2d, 0xe5, 0x7a, 0x9f, 0x93, 0xc9, 0x9c, 0xef,
            0xa0, 0xe0, 0x3b, 0x4d, 0xae, 0x2a, 0xf5, 0xb0, 0xc8, 0xeb, 0xbb, 0x3c, 0x83, 0x53, 0x99, 0x61,
            0x17, 0x2b, 0x04, 0x7e, 0xba, 0x77, 0xd6, 0x26, 0xe1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0c, 0x7d};

    /**
     * Количество столбцов (32-битных слов), составляющих state.
     * Для этого стандарта Nb = 4
     */
    private static final int Nb = 4;
    /**
     * Количество 32-битных слов,
     * составляющих ключ шифрования. Для этого стандарта Nk = 4, 6 или 8
     */
    private int Nk;
    /**
     * Количество раундов, которое является функцией Nk и Nb.
     * Для этого стандарта Nr = 10, 12 или 14
     */
    private int Nr;
    /**
     * массив для хранения ключа 16-, 24- или 32- байтных
     */
    private int[] key;

    /**
     * массив для хранения линейного массива из 32 битных слов, полученных на основе ключа
     * Этого достаточно,
     * чтобы обеспечить раундовый ключ из четырех слов
     * для начальной стадии AddRoundKey и каждого из Nr раундов шифрования
     * Например, адлогитм расширения ключей даст 44 слова для 16-байтного ключа
     */
    private int[] w;

    /**
     * загрузка ключей и инициализация массива для хранения расширенных ключей
     *
     * @param textKey - ключ
     */
    public void uploadKey(String textKey) {
        var key = textKey.getBytes();
        this.key = new int[key.length];

        for (int i = 0; i < key.length; i++) {
            this.key[i] = key[i] & 0xFF000000;
        }

        switch (key.length) {
            case 16:
                Nr = 10;
                Nk = 4;
                break;
            case 24:
                Nr = 12;
                Nk = 6;
                break;
            case 32:
                Nr = 14;
                Nk = 8;
                break;
        }
        w = new int[Nb * (Nr + 1)];
        keyExpansion();
    }

    /**
     * расширяю ключи по алгоритму
     * псевдокод:
     * KeyExpansion(byte key[4*Nk], word w[Nb*(Nr+1)], Nk)
     * begin
     * word temp
     * i = 0
     * while (i < Nk)
     * w[i] = word(key[4*i], key[4*i+1], key[4*i+2], key[4*i+3])
     * i = i+1
     * end while
     * i = Nk
     * while (i < Nb * (Nr+1)]
     * temp = w[i-1]
     * if (i mod Nk = 0)
     * temp = SubWord(RotWord(temp)) xor Rcon[i/Nk]
     * else if (Nk > 6 and i mod Nk = 4)
     * temp = SubWord(temp)
     * end if
     * w[i] = w[i-Nk] xor temp
     * i = i + 1
     * end while
     * end
     */
    private void keyExpansion() {
        int temp, i = 0;
        while (i < Nk) {
            w[i] = word(key[4 * i], key[4 * i + 1], key[4 * i + 2], key[4 * i + 3]);
            i++;
        }
        i = Nk;
        while (i < Nb * (Nr + 1)) {
            temp = w[i - 1];
            if (i % Nk == 0) {
                temp = subWord(rotWord(temp)) ^ rCon[(i / Nk) - 1];
            } else if (Nk > 6 && (i % Nk == 4)) {
                temp = subWord(temp);
            }
            w[i] = w[i - Nk] ^ temp;
            i++;
        }
    }

    /**
     * строю слово из 4 байт или из 32 бит.
     * Передвигаю b1 влево на 24 знака в бинарном представлении
     * Передвигаю b2 влево на 16 знаков в бинарном представлении
     * Передвигаю b3 влево на 8 знаков в бинарном представлении
     * Добавляю b4 в конец
     * использую or для конткатенации
     * Например слово состоит из 4 симоволов [81, 107, 67, 76]
     * в бинарном представлении [1010001,1101011,1000011,1001100]
     * в итоге получила слово:
     *
     * @return слово 1010001 01101011 01000011 01001100 - или 1365984076 в десятичном представлении
     */
    private int word(int b1, int b2, int b3, int b4) {
        int word = 0;
        word |= (b1) << 24;
        word |= (b2) << 16;
        word |= (b3) << 8;
        word |= (b4);
        return word;
    }

    /**
     * смещение
     * пример из статьи: 0914dff4 -> 14dff409
     *
     * @param word слово
     * @return слово в представлении int
     */
    private int rotWord(int word) {
        return (word << 8) | (word & 0xFF000000) >>> 24;
    }

    /**
     * subWord() — это функция, которая принимает входное четырехбайтовое слово и
     * применяет S-блок к каждому из четырех байтов для создания выходного слова.
     * Замена основана на значении каждого из 4 частей слова. Значение 8 бит слова определяет
     * индекс массива suBox[значение]
     *
     * @param word 32-битное слово
     * @return слово в представлении int
     */
    private int subWord(int word) {
        int subWord = 0;
        for (int i = 0; i < 25; i += 8) {
            //например, берем первые 8 бит из слова - 01010001 01101011 01000011 01001100
            // при i = 0, перемещаем 01010001 вправо на 24 бита, получается - 00000000 00000000 00000000 01010001 или 81 в десятичном ичсислении
            //для i = 1 01101011 ставим влево на место 01010001, затем перемещаем 01101011 вправо на 24 бита
            int in = word << i >>> 24;
            //берем элемент 81 элемент из sBox, при i = 0, перемещаем значение, хранящееся в массиве побитово на 24 бита влево
            subWord |= sBox[in] << 24 - i;
        }
        return subWord;
    }

    /**
     * @param text входящий текст, разбивается на блоки из 16 байт, или 128 битов
     * @return зашифрованный текст
     */
    public byte[] encryptECB(byte[] text) {
        try (ByteArrayOutputStream out = new ByteArrayOutputStream()) {
            for (int i = 0; i < text.length; i += 16) {
                out.write(encrypt(Arrays.copyOfRange(text, i, i + 16)));
            }
            return out.toByteArray();
        } catch (IOException e) {
            throw new HttpServerErrorException(HttpStatus.INTERNAL_SERVER_ERROR);
        }
    }

    /**
     * @param file входящий файл для зашифрования, расширение txt,
     *             Считывается построчно
     *             Строки разбиваются на блоки из 16 байт, или 128 битов
     * @return файл с зашифрованным текстом в формате base64
     */
    public byte[] encryptECBFile(MultipartFile file) {
        try (ByteArrayOutputStream baos = new ByteArrayOutputStream();
             var bufferedWriter = new BufferedWriter(new OutputStreamWriter(baos)); InputStream inputStream = file.getInputStream(); Scanner sc = new Scanner(inputStream, StandardCharsets.UTF_8)) {
            while (sc.hasNextLine()) {
                String line = sc.nextLine();
                bufferedWriter.write(Base64.getEncoder().encodeToString(encryptECB(fillBlock(line).getBytes())));
                bufferedWriter.newLine();
            }
            bufferedWriter.flush();
            if (sc.ioException() != null) {
                throw sc.ioException();
            }
            return baos.toByteArray();
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
    }

    /**
     * функция для зашифровки и инициализации массива state на этапе зашифровки
     *
     * @param in 128 бит
     * @return зашифрованный текст
     */
    private byte[] encrypt(byte[] in) {
        byte[] out = new byte[4 * Nb];
        int[][] state = initState(in);

        cipher(state);
        for (int i = 0; i < Nb; i++) {
            for (int j = 0; j < 4; j++) {
                out[i * Nb + j] = (byte) (state[j][i] & 0xff);
            }
        }
        return out;
    }

    /**
     * функция для зашифровки
     * содержит 4 основных функции для шифрования AddRoundKey, SubBytes, ShiftRows, MixColumns
     * Псевдокод:
     * Cipher(byte in[4*Nb], byte out[4*Nb], word w[Nb*(Nr+1)])
     * begin
     * byte state[4,Nb]
     * state = in
     * AddRoundKey(state, w[0, Nb-1]) // See Sec. 5.1.4
     * for round = 1 step 1 to Nr–1
     * SubBytes(state) // See Sec. 5.1.1
     * ShiftRows(state) // See Sec. 5.1.2
     * MixColumns(state) // See Sec. 5.1.3
     * AddRoundKey(state, w[round*Nb, (round+1)*Nb-1])
     * end for
     * SubBytes(state)
     * ShiftRows(state)
     * AddRoundKey(state, w[Nr*Nb, (Nr+1)*Nb-1])
     * out = state
     * end
     *
     * @param state - массив состояния
     */
    private void cipher(int[][] state) {
        addRoundKey(state, 0);

        for (var round = 1; round < Nr; round++) {
            subBytes(state);
            shiftRows(state);
            mixColumns(state);
            addRoundKey(state, round);
        }
        subBytes(state);
        shiftRows(state);
        addRoundKey(state, Nr);
    }

    /**
     * матрица состояния - state, имеющая Nb столбцов и 4 строки
     * round - раунд ключа w, который нужно добавить
     * Раундовый ключ добавляется к состоянию простым побитовым - Операция XOR
     * Напимер, round = 0 и w[0]=[01010001 01101011 01000011 01001100], state[0][0] = 11111111 тогда:
     * c=0:
     * state[0][0] = state[0][0]XOR(w[0]<< (0 * 8)) >>> 24)
     * или
     * state[0][0] = 11111111 XOR 00000000 00000000 00000000 01010001 = 10101110
     * <p>
     * Хочу отметить, что данная запись - (w[round * Nb + c] << (r * 8)) >>> 24
     * со сдвигом 32 битной записи сначала на r * 8 влево и затем на 24 вправо,
     * позволяет вычленять 8 соответсвующих бит из 32-битной записи - после этой операции получу
     * при r=0 - 00000000 00000000 00000000 01010001
     */
    private void addRoundKey(int[][] state, int round) {
        for (int c = 0; c < Nb; c++) {
            for (int r = 0; r < 4; r++) {
                state[r][c] = state[r][c] ^ ((w[round * Nb + c] << (r * 8)) >>> 24);
            }
        }
    }

    /**
     * Преобразование SubBytes() — это нелинейная замена байтов,
     * которая работает независимо.
     * На каждом байте массива состояния State с помощью таблицы подстановки (S-box)
     * Или другими словами - заменяю state значениями из матрицы S-Box по индексам, который определяется самим
     * же значением в state
     */
    private void subBytes(int[][] state) {
        for (int i = 0; i < 4; i++) {
            for (int j = 0; j < Nb; j++) {
                state[i][j] = subWord(state[i][j]) & 0xFF;
            }
        }
    }

    /**
     * В преобразовании ShiftRows() байты в последних
     * трех строках массива состояния STATE циклически сдвигаются.
     * Первая строка, r = 0, не сдвигается, строка 4 - сдвигается на 3 позиции
     *
     * @param state массив состояния
     */
    private void shiftRows(int[][] state) {
        for (int i = 1; i < 4; i++) {
            shift(i, state);
        }
    }

    private void shift(int offset, int[][] state) {
        int[] tempState = new int[offset];
        System.arraycopy(state[offset], 0, tempState, 0, offset);

        for (var i = 0; i < Nb - offset; i++) {
            state[offset][i] = state[offset][(i + offset) % Nb];
        }
        for (var i = 0; i < offset; i++) {
            state[offset][Nb - (offset - i)] = tempState[i];
        }

    }

    /**
     * Перемешивание колонок матрицы состояния
     * путем определенных операций с матрицей state
     *
     * @param state перемешанная state
     */
    private void mixColumns(int[][] state) {
        int temp0, tempState1, temp2, tempState3;
        for (int c = 0; c < Nb; c++) {

            temp0 = mult(0x02, state[0][c]) ^ mult(0x03, state[1][c]) ^ state[2][c] ^ state[3][c];
            tempState1 = state[0][c] ^ mult(0x02, state[1][c]) ^ mult(0x03, state[2][c]) ^ state[3][c];
            temp2 = state[0][c] ^ state[1][c] ^ mult(0x02, state[2][c]) ^ mult(0x03, state[3][c]);
            tempState3 = mult(0x03, state[0][c]) ^ state[1][c] ^ state[2][c] ^ mult(0x02, state[3][c]);

            state[0][c] = temp0;
            state[1][c] = tempState1;
            state[2][c] = temp2;
            state[3][c] = tempState3;
        }

    }

    /**
     * Для алгоритма AES неприводимый многочлен равен m(x) = x^8 + x^4 + x^3 + x +1 или
     * в шеснадцатиричной нотации - 0x11b (283)
     * По примеру из статьи
     * {57} • {13} = {fe}
     * {57} • {02} = xtime({57}) = {ae}
     * {57} • {04} = xtime({ae}) = {47}
     * {57} • {08} = xtime({47}) = {8e}
     * {57} • {10} = xtime({8e}) = {07}
     * <p>
     * {57} • ({01} xor {02} xor {10}) = {57} xor {ae} xor {07}
     * <p>
     * например, для {02} будем иметь {b}•({02}) или - xtime({b})
     * для {03} будем иметь {b}•({01}xor{02}) или {b}^xtime({b})
     *
     * @return результат мультипликации
     */
    private int mult(int a, int b) {
        // {b}*{(01)xor{02}} для 3
        // {b}*{{02}} для 2
        int tmpB = 0;
        while (a != 0) {
            //определяю нечетность по наименьшему биту
            if ((a & 1) != 0) {
                //собираем
                tmpB = tmpB ^ b;
            }
            b = xtime(b); // умножение многочлена на x;
            //0111>0011
            a = a >>> 1; //отнимаем сразу 2 в dec
        }

        return tmpB;
    }

    /**
     * умножение на x ( x = {02} в поле GF(2^8) ) это сдвиг влево многочлена b на один бит
     * Например,
     * Умножим 0000 0010 на  1111 1111 (или 2 на 255 по модулю 283)
     * Если у b до сдвига ведущий бит был равен 1 при помощи (b & 0X80) проверяем это условие,
     * Отстаток от деления будет вероятно, полученный результат надо будет отнять от многочлена (283)
     * После сдвига получаем: 11111 1110 xor 10001 1011 = 1110 0101
     *
     * @return отстаток от деления
     */
    private int xtime(int b) {
        return (b & 0x80) == 0 ?
                b << 1 : (b << 1) ^ 0x11b;
    }

    /**
     * дополняю блоки пустой строкой, если они короче 16
     *
     * @param text входной текст
     * @return текст
     */
    public String fillBlock(String text) {
        int spaceNum = text.getBytes().length % 16 == 0 ? 0 : 16 - text.getBytes().length % 16;
        text = text + " ".repeat(spaceNum);
        return text;
    }

    /**
     * Для дешифрования зашифрованного файла
     *
     * @param file файл с зашифрованным содержимым
     * @return расшифрованный массив байт
     */
    public byte[] decryptECBFile(MultipartFile file) {
        try (ByteArrayOutputStream baos = new ByteArrayOutputStream();
             var bufferedWriter = new BufferedWriter(new OutputStreamWriter(baos)); InputStream inputStream = file.getInputStream(); Scanner sc = new Scanner(inputStream, StandardCharsets.UTF_8)) {
            while (sc.hasNextLine()) {
                String line = sc.nextLine();
                bufferedWriter.write(new String(decryptECB(Base64.getDecoder().decode(line))));
                bufferedWriter.newLine();
            }
            bufferedWriter.flush();
            if (sc.ioException() != null) {
                throw sc.ioException();
            }
            return baos.toByteArray();
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
    }

    /**
     * Для дешифрования введенной фразы
     * зашифрованная фраза зашифрованным
     *
     * @return расшифрованный массив байт
     */
    public byte[] decryptECB(byte[] text) {
        try (ByteArrayOutputStream out = new ByteArrayOutputStream()) {
            for (int i = 0; i < text.length; i += 16) {
                out.write(decrypt(Arrays.copyOfRange(text, i, i + 16)));
            }
            return out.toByteArray();
        } catch (IOException e) {
            throw new HttpServerErrorException(HttpStatus.INTERNAL_SERVER_ERROR);
        }

    }

    /**
     * функция для дешифрования и инициализации массива state на этапе зашифровки
     *
     * @param in 128 бит
     * @return зашифрованный текст
     */
    private byte[] decrypt(byte[] in) {
        byte[] out = new byte[4 * Nb];
        int[][] state = initState(in);

        decipher(state);
        for (int i = 0; i < Nb; i++) {
            for (int j = 0; j < 4; j++) {
                out[i * Nb + j] = (byte) (state[j][i] & 0xff);
            }
        }
        return out;

    }

    /**
     * функция для инициализации массива состояния - state
     *
     * @param in 128 бит
     * @return зашифрованный текст
     */
    private int[][] initState(byte[] in) {
        var state = new int[4][Nb];

        for (int i = 0; i < Nb; i++) {
            for (int j = 0; j < 4; j++) {
                state[j][i] = in[i * Nb + j] & 0xff;
            }
        }
        return state;
    }

    /**
     * основаная функция для дешифрования
     * псевдокод:
     * InvCipher(byte in[4*Nb], byte out[4*Nb], word w[Nb*(Nr+1)])
     * begin
     * byte state[4,Nb]
     * state = in
     * AddRoundKey(state, w[Nr*Nb, (Nr+1)*Nb-1]) // See Sec. 5.1.4
     * for round = Nr-1 step -1 downto 1
     * InvShiftRows(state) // See Sec. 5.3.1
     * InvSubBytes(state) // See Sec. 5.3.2
     * AddRoundKey(state, w[round*Nb, (round+1)*Nb-1])
     * InvMixColumns(state) // See Sec. 5.3.3
     * end for
     * InvShiftRows(state)
     * InvSubBytes(state)
     * AddRoundKey(state, w[0, Nb-1])
     * out = state
     * end
     */
    private void decipher(int[][] state) {
        var round = Nr;
        addRoundKey(state, round);
        for (round = Nr - 1; round > 0; round--) {
            invShiftRows(state);
            invSubBytes(state);
            addRoundKey(state, round);
            invMixColumns(state);
        }
        invShiftRows(state);
        invSubBytes(state);
        addRoundKey(state, round);

    }

    /**
     * InvShiftRows() является обратным преобразованию ShiftRows().
     * Байты в последних трех строках состояния циклически сдвигаются
     * на разное количество байтов (смещения).
     * Первая строка r = 0 не сдвигается.
     * Нижние три строки циклически сдвигаются на Nb - сдвиг(r, Nb) байт
     *
     * @param state измененная матрица состояния
     */

    private void invShiftRows(int[][] state) {
        for (int i = 1; i < 4; i++) {
            invShift(i, state);
        }
    }

    /**
     * функция помогает сделать сдиг
     */
    private void invShift(int offset, int[][] state) {
        int[] tempState = new int[offset];
        for (int i = 0; i < offset; i++) {
            tempState[i] = state[offset][Nb - (offset - i)];
        }
        for (int i = Nb - 1; i > (offset - 1); i--) {
            state[offset][i] = state[offset][(i - offset) % Nb];
        }
        System.arraycopy(tempState, 0, state[offset], 0, offset);
    }

    /**
     * InvSubBytes() является обратным преобразованию замены байтов,
     * в котором обратный S-блок (rsBox) применяется к каждому байту матрицы состояния.
     * @param state матрица состояния преобразованная
     */
    private void invSubBytes(int[][] state) {
        for (int i = 0; i < 4; i++) {
            for (int j = 0; j < Nb; j++) {
                state[i][j] = invSubWord(state[i][j]) & 0xFF;
            }
        }
    }

    private int invSubWord(int word) {
        int subWord = 0;
        for (int i = 0; i < 25; i += 8) {
            //например, берем первые 8 бит из слова - 01010001 01101011 01000011 01001100
            // при i = 0, перемещаем 01010001 вправо на 24 бита, получается - 00000000 00000000 00000000 01010001 или 81 в десятичном ичсислении
            //для i = 1 01101011 ставим влево на место 01010001, затем перемещаем 01101011 вправо на 24 бита
            int in = word << i >>> 24;
            //берем элемент 81 элемент из rsBox, при i = 0, перемещаем значение, хранящееся в массиве побитово на 24 бита влево
            subWord |= rsBox[in] << 24 - i;
        }
        return subWord;
    }

    /**
     * InvMixColumns() является обратным преобразованию MixColumns().
     * InvMixColumns() работает с матрицей state столбец за столбцом.
     * @param state матрица состояния
     */
    private void invMixColumns(int[][] state) {
        int tempState0, tempState1, tempState2, tempState3;
        for (int c = 0; c < Nb; c++) {
            tempState0 = mult(0x0e, state[0][c]) ^ mult(0x0b, state[1][c]) ^ mult(0x0d, state[2][c]) ^ mult(0x09, state[3][c]);
            tempState1 = mult(0x09, state[0][c]) ^ mult(0x0e, state[1][c]) ^ mult(0x0b, state[2][c]) ^ mult(0x0d, state[3][c]);
            tempState2 = mult(0x0d, state[0][c]) ^ mult(0x09, state[1][c]) ^ mult(0x0e, state[2][c]) ^ mult(0x0b, state[3][c]);
            tempState3 = mult(0x0b, state[0][c]) ^ mult(0x0d, state[1][c]) ^ mult(0x09, state[2][c]) ^ mult(0x0e, state[3][c]);

            state[0][c] = tempState0;
            state[1][c] = tempState1;
            state[2][c] = tempState2;
            state[3][c] = tempState3;
        }
    }
}
