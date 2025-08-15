#include <print>

#include "cmd_options.h"

namespace CryptoGuard {

namespace po = boost::program_options;

ProgramOptions::ProgramOptions() : desc_("Allowed options") {
    desc_.add_options()("help,h", "Show help message")("command,c", po::value<std::string>()->required(),
                                                       "Command to execute: encrypt, decrypt or checksum")(
        "input,i", po::value<std::string>()->required(), "Input file path")(
        "output,o", po::value<std::string>(), "Output file path")("password,p", po::value<std::string>(),
                                                                  "Password for encryption/decryption");
}

ProgramOptions::~ProgramOptions() = default;

void ProgramOptions::Parse(int argc, char *argv[]) {

    po::variables_map vm;
    po::store(po::parse_command_line(argc, argv, desc_), vm);

    if (vm.count("help")) {
        std::ostringstream oss;
        oss << desc_;
        std::print(stdout, "{}", oss.str());
        return;
    }

    po::notify(vm);

    // Parse command
    std::string cmd = vm["command"].as<std::string>();
    if (auto it = commandMapping_.find(cmd); it != commandMapping_.end()) {
        command_ = it->second;
    } else {
        throw po::error("Invalid command specified");
    }

    // Set other parameters
    inputFile_ = vm["input"].as<std::string>();

    if (auto it = vm.find("output"); it != vm.end()) {
        outputFile_ = it->second.as<std::string>();
    } else if (command_ == COMMAND_TYPE::ENCRYPT || command_ == COMMAND_TYPE::DECRYPT) {
        throw po::error("Output is required for encryption/decryption");
    }

    if (auto it = vm.find("password"); it != vm.end()) {
        password_ = it->second.as<std::string>();
    } else if (command_ == COMMAND_TYPE::ENCRYPT || command_ == COMMAND_TYPE::DECRYPT) {
        throw po::error("Password is required for encryption/decryption");
    }
}

}  // namespace CryptoGuard
