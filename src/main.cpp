#include "cmd_options.h"
#include "crypto_guard_ctx.h"
#include <fstream>
#include <iostream>
#include <print>
#include <stdexcept>

// Проверка открытия файлов в main по причине того, что в таком случае
// ошибка для пользователя получается более явной - он видит имя некорректного файла
std::fstream open_file(const std::string &name) {

    std::fstream file(name);

    if (!file.is_open()) {
        throw std::runtime_error(std::format("Не удалось открыть файл: {}", name));
    }

    return file;
}

int main(int argc, char *argv[]) {
    try {

        CryptoGuard::ProgramOptions options;

        try {
            options.Parse(argc, argv);
        } catch (const boost::program_options::error &e) {
            std::cerr << "Error: " << e.what() << "\n";
            exit(1);
        }

        CryptoGuard::CryptoGuardCtx cryptoCtx;

        using COMMAND_TYPE = CryptoGuard::ProgramOptions::COMMAND_TYPE;
        switch (options.GetCommand()) {
        case COMMAND_TYPE::ENCRYPT: {

            std::fstream input_stream = open_file(options.GetInputFile());
            std::fstream output_stream = open_file(options.GetOutputFile());

            cryptoCtx.EncryptFile(input_stream, output_stream, options.GetPassword());
            std::print("File encoded successfully\n");
            break;
        }

        case COMMAND_TYPE::DECRYPT: {

            std::fstream input_stream = open_file(options.GetInputFile());
            std::fstream output_stream = open_file(options.GetOutputFile());

            cryptoCtx.DecryptFile(input_stream, output_stream, options.GetPassword());

            std::print("File decoded successfully\n");
            break;
        }

        case COMMAND_TYPE::CHECKSUM: {

            std::fstream input_stream = open_file(options.GetInputFile());

            cryptoCtx.CalculateChecksum(input_stream);

            std::print("Checksum: {}\n", "CHECKSUM_NOT_IMPLEMENTED");
            break;
        }
        default:
            throw std::runtime_error{"Unsupported command"};
        }

    } catch (const std::exception &e) {
        std::print(std::cerr, "Error: {}\n", e.what());
        return 1;
    }

    return 0;
}