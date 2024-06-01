#include <iostream>
#include <unordered_map>

#include <aes.hpp>
#include <HttpRequest.hpp>
#include <json.hpp>
#include <Pattern.hpp>
#include <Process.hpp>
#include <ProcessHandle.hpp>
#include <string.hpp>

using namespace soup;

static const uint8_t key[16] = { 76, 69, 79, 45, 65, 76, 69, 67, 9, 69, 79, 45, 65, 76, 69, 67 };
static const uint8_t iv[16] = { 49, 50, 70, 71, 66, 51, 54, 45, 76, 69, 51, 45, 113, 61, 57, 0 };

[[nodiscard]] static std::string gruzzleNonce(const ProcessHandle& mod)
{
	std::cout << "Gruzzling";
	std::unordered_map<std::string, int> candidates{};
	const auto pattern = Pattern("6E 6F 6E 63 65 3D"); // nonce=
	for (const auto& r : mod.getAllocations())
	{
		if (auto res = mod.externalScan(r, pattern))
		{
			res = res.add(6);
			std::string nonce;
			char c;
			do
			{
				c = mod.externalRead<char>(res);
				res = res.add(1);
			} while (string::isNumberChar(c) && (nonce.push_back(c), true));
			std::cout << ".";
			if (auto e = candidates.find(nonce); e != candidates.end())
			{
				if (++e->second == 3)
				{
					std::cout << " The crumbs have been gruzzled." << std::endl;
					return nonce;
				}
			}
			else
			{
				candidates.emplace(nonce, 1);
			}
		}
	}
	std::cout << " Failed to gruzzle the crumbs." << std::endl;
	return {};
}

int main()
{
	auto proc = Process::get("Warframe.x64.exe");
	if (!proc)
	{
		std::cout << "Process not found." << std::endl;
		system("pause > nul");
		return 1;
	}
	auto mod = proc->open();
	SOUP_IF_UNLIKELY (!mod)
	{
		std::cout << "Failed to open process." << std::endl;
		system("pause > nul");
		return 2;
	}
	auto nonce = gruzzleNonce(*mod);
	SOUP_IF_UNLIKELY (nonce.empty())
	{
		system("pause > nul");
		return 3;
	}
	const std::filesystem::path localappdata = _wgetenv(L"localappdata");
	auto eelog = string::fromFile(localappdata / "Warframe" / "EE.log");
	auto i = eelog.find("AccountId: ");
	SOUP_IF_UNLIKELY (i == std::string::npos)
	{
		std::cout << "Failed to find AccountId." << std::endl;
		system("pause > nul");
		return 4;
	}
	i += 11;
	auto accountId = eelog.substr(i, eelog.find("\r\n", i) - i);
	std::cout << "?accountId=" + accountId + "&nonce=" + nonce << std::endl;
	std::cout << "Downloading inventory... ";
	// Note: Could also use api.warframe.com
	HttpRequest hr("mobile.warframe.com", "/api/inventory.php?accountId=" + accountId + "&nonce=" + nonce);
	auto res = hr.execute();
	SOUP_IF_UNLIKELY (!res)
	{
		std::cout << "Request failed." << std::endl;
		system("pause > nul");
		return 5;
	}
	auto inventory = std::move(res->body);
	auto jr = json::decode(inventory);
	SOUP_IF_UNLIKELY (!jr)
	{
		std::cout << "Received an invalid response." << std::endl;
		system("pause > nul");
		return 6;
	}
	string::toFile("inventory.json", jr->encodePretty());
	aes::pkcs7Pad(inventory);
	aes::cbcEncrypt(
		reinterpret_cast<uint8_t*>(inventory.data()), inventory.size(),
		key, 16,
		iv
	);
	string::toFile("lastData.dat", inventory);
	std::cout << "Saved to inventory.json & lastData.dat in working directory." << std::endl;
	system("pause > nul");
	return 0;
}
