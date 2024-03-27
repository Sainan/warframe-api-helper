#include <iostream>
#include <unordered_map>

#include <aes.hpp>
#include <HttpRequest.hpp>
#include <Module.hpp>
#include <Pattern.hpp>
#include <Process.hpp>
#include <string.hpp>

using namespace soup;

static const uint8_t key[16] = { 76, 69, 79, 45, 65, 76, 69, 67, 9, 69, 79, 45, 65, 76, 69, 67 };
static const uint8_t iv[16] = { 49, 50, 70, 71, 66, 51, 54, 45, 76, 69, 51, 45, 113, 61, 57, 0 };

[[nodiscard]] static std::string gruzzleNonce(const Module& mod)
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
					std::cout << " The crumbs have been gruzzled.\n";
					return nonce;
				}
			}
			else
			{
				candidates.emplace(nonce, 1);
			}
		}
	}
	std::cout << " Failed to gruzzle the crumbs.\n";
	return {};
}

int main()
{
	auto proc = Process::get("Warframe.x64.exe");
	if (!proc)
	{
		std::cout << "Process not found.\n";
		system("pause > nul");
		return 1;
	}
	auto mod = proc->open();
	if (!mod)
	{
		std::cout << "Failed to open process.\n";
		system("pause > nul");
		return 2;
	}
	auto nonce = gruzzleNonce(*mod);
	if (nonce.empty())
	{
		system("pause > nul");
		return 3;
	}
	const std::filesystem::path localappdata = _wgetenv(L"localappdata");
	auto eelog = string::fromFile(localappdata / "Warframe" / "EE.log");
	auto i = eelog.find("AccountId: ");
	if (i == std::string::npos)
	{
		std::cout << "Failed to find AccountId.\n";
		system("pause > nul");
		return 4;
	}
	i += 11;
	auto accountId = eelog.substr(i, eelog.find("\r\n", i) - i);
	std::cout << "Checking the docket...";
	HttpRequest hr("mobile.warframe.com", "/api/inventory.php?accountId=" + accountId + "&nonce=" + nonce);
	auto res = hr.execute();
	auto inventory = std::move(res->body);
	aes::pkcs7Pad(inventory);
	aes::cbcEncrypt(
		reinterpret_cast<uint8_t*>(inventory.data()), inventory.size(),
		key, 16,
		iv
	);
	string::toFile(localappdata / "AlecaFrame" / "lastData.dat", inventory);
	std::cout << " Swazdo-Lah.\n";
	std::cout << "\nAll done! Restart AlecaFrame now to see your up-to-date game data.\n";
	system("pause > nul");
	return 0;
}
