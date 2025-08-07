#include "crypto_guard_ctx.h"  // Заголовочный файл с CryptoGuardCtx
#include <gtest/gtest.h>
#include <sstream>
#include <stdexcept>

class CipherTest : public ::testing::Test {
protected:
    void SetUp() override {
        // Тестовые данные
        plaintext_ = "Some interesting text to test the operation of the encoder class.";
        password_ = "strong_password";
    }

    std::unique_ptr<CryptoGuard::CryptoGuardCtx> ctx_ = std::make_unique<CryptoGuard::CryptoGuardCtx>();
    std::string plaintext_;
    std::string password_;
};

// Те
TEST_F(CipherTest, EncryptDecryptRoundtrip) {
    std::stringstream input(plaintext_);
    std::stringstream encrypted;
    std::stringstream decrypted;

    EXPECT_NO_THROW(ctx_->EncryptFile(input, encrypted, password_))
        << "Процесс шифровки должен быть корректен в данном случае";

    encrypted.seekg(0);
    EXPECT_NO_THROW(ctx_->DecryptFile(encrypted, decrypted, password_))
        << "Процесс дешифровки должен быть корректен в данном случае (пароль верный)";

    // Проверка совпадения начального и конечного текстов
    EXPECT_EQ(plaintext_, decrypted.str())
        << "Изначальный текст и полученный в результате шифровки/дешифровки должны быть одинаковы";

    // Проверка совпадения начальной и конечной контрольной суммы
    std::stringstream input_second(plaintext_);
    decrypted.seekg(0);
    EXPECT_EQ(ctx_->CalculateChecksum(input_second), ctx_->CalculateChecksum(decrypted))
        << "Контрольные суммы для изначального и полученного текста должны быть одинаковы";
}

TEST_F(CipherTest, EmptyInputEncode) {
    std::stringstream input("");
    std::stringstream encrypted;
    std::stringstream decrypted;

    EXPECT_NO_THROW(ctx_->EncryptFile(input, encrypted, password_))
        << "Не должно возникать проблем при шифровке пустого текста";

    encrypted.seekg(0);
    EXPECT_NO_THROW(ctx_->DecryptFile(encrypted, decrypted, password_))
        << "Не должно возникать проблем при дешифровке пустого текста";

    EXPECT_TRUE(decrypted.str().empty()) << "Дешифрованный текст от изначального пустого должен быть пустым";
}

TEST_F(CipherTest, PasswordChange) {
    std::stringstream input(plaintext_);
    std::stringstream encrypted;

    // Шифруем с паролем 1
    EXPECT_NO_THROW(ctx_->EncryptFile(input, encrypted, "correct_password"));
    ASSERT_THROW(ctx_->EncryptFile(input, encrypted, "correct_password"), std::runtime_error)
        << "Входной поток уже прочитан, должен стать невалидным";

    // Пробуем дешифровать с паролем 2 (должно быть ошибкой)
    std::stringstream encrypted_copy1;
    encrypted_copy1 << encrypted.rdbuf();
    encrypted_copy1.seekg(0);
    std::stringstream decrypted_fail;

    // в случае неверного пароля должно выбросится исключение c определенным текстом и типом
    EXPECT_NO_THROW(
        try {
            ctx_->DecryptFile(encrypted_copy1, decrypted_fail, "wrong_password");
            FAIL() << "При дешифровке текста с неверным паролем должно выбрасываться исключение";
        } catch (const std::runtime_error &e) {
            std::string msg = e.what();
            EXPECT_TRUE(msg.starts_with("OpenSSL CipherFinal operation failed: "))
                << "Текст исключения в случае неверного пароля должен начинаться с \"OpenSSL CipherFinal operation "
                   "failed: \" ";
        })
        << "Тип исключения при дешифровке с неправильным ключом должен быть std::runtime_error";

    // Дешифруем с правильным паролем
    std::stringstream encrypted_copy2;
    encrypted.seekg(0);
    encrypted_copy2 << encrypted.rdbuf();
    encrypted_copy2.seekg(0);
    std::stringstream decrypted_success;
    EXPECT_NO_THROW(ctx_->DecryptFile(encrypted_copy2, decrypted_success, "correct_password"));
    ASSERT_THROW(ctx_->DecryptFile(encrypted_copy2, decrypted_success, "correct_password"), std::runtime_error)
        << "Входной поток уже прочитан, должен стать невалидным";

    EXPECT_EQ(plaintext_, decrypted_success.str())
        << "Дешифровка с неверным паролем не должна влиять на процесс работы с правильным паролем";
}

TEST_F(CipherTest, LargeDataEncryption) {
    std::string large_data(1024 * 1024, 'X');  // 1MB данных
    std::stringstream input(large_data);
    std::stringstream encrypted;
    std::stringstream decrypted;

    EXPECT_NO_THROW(ctx_->EncryptFile(input, encrypted, password_))
        << "Не должно возникать проблем при шифровке очень большого текста";

    encrypted.seekg(0);
    EXPECT_NO_THROW(ctx_->DecryptFile(encrypted, decrypted, password_))
        << "Не должно возникать проблем при дешифровке очень большого текста";

    EXPECT_EQ(large_data, decrypted.str()) << "Большие данные должны правильно проходить процесс шифровки/дешифровки";
}

TEST_F(CipherTest, MultipleOperations) {
    std::stringstream input1("First message");
    std::stringstream input2("Second message");
    std::stringstream encrypted1, encrypted2;
    std::stringstream decrypted1, decrypted2;

    // Первая операция
    EXPECT_NO_THROW(ctx_->EncryptFile(input1, encrypted1, "pass1"));

    // Вторая операция с другим паролем
    EXPECT_NO_THROW(ctx_->EncryptFile(input2, encrypted2, "pass2"))
        << "Не должно возникать проблем при шифровке разных текстов в рамках одного класса";

    // Дешифровка
    encrypted1.seekg(0);
    EXPECT_NO_THROW(ctx_->DecryptFile(encrypted1, decrypted1, "pass1"));

    encrypted2.seekg(0);
    EXPECT_NO_THROW(ctx_->DecryptFile(encrypted2, decrypted2, "pass2"))
        << "Не должно возникать проблем при дешифровке разных текстов в рамках одного класса";

    EXPECT_EQ("First message", decrypted1.str());
    EXPECT_EQ("Second message", decrypted2.str());
}

TEST_F(CipherTest, InvalidInputOutputStreams) {
    // 1. Невалидный входной поток (badbit)
    {
        std::stringstream bad_input;
        bad_input.setstate(std::ios::badbit);  // Имитируем аппаратный сбой
        std::stringstream output;

        EXPECT_NO_THROW(
            try {
                ctx_->EncryptFile(bad_input, output, "pass2");
                FAIL() << "При работе с невалидным входным потоком (badbit) должно выбрасываться исключение";
            } catch (const std::runtime_error &e) {
                std::string msg = e.what();
                EXPECT_EQ(msg, "Input stream is in bad state")
                    << "Текст исключения в случае невалидного входного потока (badbit) должен быть \"Input stream is "
                       "in bad state\" ";
            })
            << "Тип исключения при работе с невалидным входным потоком (badbit) должен быть std::runtime_error";
    }

    // 2. Невалидный выходной поток
    {
        std::stringstream input(plaintext_);
        std::stringstream bad_output;
        bad_output.setstate(std::ios::badbit);

        EXPECT_NO_THROW(
            try {
                ctx_->DecryptFile(input, bad_output, "pass2");
                FAIL() << "При работе с невалидным выходным потоком (badbit) должно выбрасываться исключение";
            } catch (const std::runtime_error &e) {
                std::string msg = e.what();
                EXPECT_EQ(msg, "Output stream is in bad state")
                    << "Текст исключения в случае невалидного выходного потока (badbit) должен быть \"Output stream is "
                       "in bad state\" ";
            })
            << "Тип исключения при работе с невалидным выходным потоком (badbit) должен быть std::runtime_error";
    }

    // 3. Поток в состоянии fail (логическая ошибка)
    {
        std::stringstream fail_input;
        fail_input.setstate(std::ios::failbit);  // Например, ошибка форматирования
        std::stringstream output;

        EXPECT_NO_THROW(
            try {
                ctx_->CalculateChecksum(fail_input);
                FAIL() << "При работе с невалидным входным потоком (failbit) должно выбрасываться исключение";
            } catch (const std::runtime_error &e) {
                std::string msg = e.what();
                EXPECT_EQ(msg, "Input stream is in bad state")
                    << "Текст исключения в случае невалидного входного потока (failbit) должен быть \"Input stream is "
                       "in bad state\" ";
            })
            << "Тип исключения при работе с невалидным входным потоком (failbit) должен быть std::runtime_error";
    }

    // 4. Поток с выставленным eofbit
    {
        std::stringstream eof_input;
        eof_input.setstate(std::ios::eofbit);  // Достигнут конец файла
        std::stringstream output;

        EXPECT_NO_THROW(
            try {
                ctx_->EncryptFile(eof_input, output, "pass2");
                FAIL() << "При работе с невалидным входным потоком (eof) должно выбрасываться исключение";
            } catch (const std::runtime_error &e) {
                std::string msg = e.what();
                EXPECT_EQ(msg, "Input stream is in bad state")
                    << "Текст исключения в случае невалидного входного потока (eof) должен быть \"Input stream is in "
                       "bad state\" ";
            })
            << "Тип исключения при работе с невалидным входным потоком (eof) должен быть std::runtime_error";
    }
}

// провека работы алгоритма на заранее заданных примерах
TEST_F(CipherTest, EmptyInputChecksum) {
    std::stringstream input("");
    EXPECT_EQ(ctx_->CalculateChecksum(input), "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855");
}

TEST_F(CipherTest, SimpleStringChecksum) {
    std::stringstream input("hello world");
    EXPECT_EQ(ctx_->CalculateChecksum(input), "b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9");
}

TEST_F(CipherTest, LargeInputChecksum) {
    std::string large_string(100000, 'x');
    std::stringstream input(large_string);
    std::string result = ctx_->CalculateChecksum(input);
    EXPECT_EQ(result.size(), 64) << "Алгоритм должен работать на больших данных";
}

TEST_F(CipherTest, BinaryDataChecksum) {
    std::string binary_data = {0x00, 0x11, 0x22, 0x33, 0x44};
    std::stringstream input(binary_data);
    std::string result = ctx_->CalculateChecksum(input);
    EXPECT_EQ(result.size(), 64);
}