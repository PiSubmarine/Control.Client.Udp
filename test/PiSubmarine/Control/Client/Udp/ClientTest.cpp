#include <gmock/gmock.h>
#include <gtest/gtest.h>

#include <cstddef>
#include <chrono>
#include <cstdint>
#include <string_view>
#include <vector>

#include "PiSubmarine/Control/Api/Input/OperatorCommand.h"
#include "PiSubmarine/Control/Client/Udp/Client.h"
#include "PiSubmarine/Control/ISerializerMock.h"
#include "PiSubmarine/Lease/Api/ILeaseIssuerMock.h"
#include "PiSubmarine/Security/Aead/Api/IProviderMock.h"
#include "PiSubmarine/Security/Nonce/Api/IProviderMock.h"
#include "PiSubmarine/Udp/Api/ISenderMock.h"

namespace PiSubmarine::Control::Client::Udp
{
    namespace
    {
        using ::testing::_;
        using ::testing::Return;
        using ::testing::StrictMock;

        constexpr std::size_t EncodedFieldSize = sizeof(std::uint32_t);

        void AppendUInt32BigEndian(std::vector<std::byte>& bytes, const std::uint32_t value)
        {
            bytes.push_back(static_cast<std::byte>((value >> 24U) & 0xFFU));
            bytes.push_back(static_cast<std::byte>((value >> 16U) & 0xFFU));
            bytes.push_back(static_cast<std::byte>((value >> 8U) & 0xFFU));
            bytes.push_back(static_cast<std::byte>(value & 0xFFU));
        }

        [[nodiscard]] std::vector<std::byte> EncodePacket(
            std::string_view leaseId,
            const std::vector<std::byte>& nonce,
            const std::vector<std::byte>& ciphertext)
        {
            std::vector<std::byte> bytes;
            bytes.reserve(EncodedFieldSize * 2 + leaseId.size() + nonce.size() + ciphertext.size());
            AppendUInt32BigEndian(bytes, static_cast<std::uint32_t>(leaseId.size()));
            for (const char character : leaseId)
            {
                bytes.push_back(static_cast<std::byte>(character));
            }

            AppendUInt32BigEndian(bytes, static_cast<std::uint32_t>(nonce.size()));
            bytes.insert(bytes.end(), nonce.begin(), nonce.end());
            bytes.insert(bytes.end(), ciphertext.begin(), ciphertext.end());
            return bytes;
        }

        [[nodiscard]] Lease::Api::LeaseGrant MakeLeaseGrant()
        {
            return Lease::Api::LeaseGrant{
                .Lease = Lease::Api::Lease{
                    .Id = Lease::Api::LeaseId{.Value = "lease-1"},
                    .Resource = Lease::Api::ResourceId{.Value = "control-main"},
                    .Duration = std::chrono::milliseconds(3000)},
                .Secret = Lease::Api::LeaseSecret{
                    .Value = {
                        std::byte{0x00}, std::byte{0x01}, std::byte{0x02}, std::byte{0x03},
                        std::byte{0x04}, std::byte{0x05}, std::byte{0x06}, std::byte{0x07},
                        std::byte{0x08}, std::byte{0x09}, std::byte{0x0A}, std::byte{0x0B},
                        std::byte{0x0C}, std::byte{0x0D}, std::byte{0x0E}, std::byte{0x0F},
                        std::byte{0x10}, std::byte{0x11}, std::byte{0x12}, std::byte{0x13},
                        std::byte{0x14}, std::byte{0x15}, std::byte{0x16}, std::byte{0x17},
                        std::byte{0x18}, std::byte{0x19}, std::byte{0x1A}, std::byte{0x1B},
                        std::byte{0x1C}, std::byte{0x1D}, std::byte{0x1E}, std::byte{0x1F}}}};
        }

        [[nodiscard]] Security::Aead::Api::Key MakeKey()
        {
            return Security::Aead::Api::Key{.Value = MakeLeaseGrant().Secret.Value};
        }

        [[nodiscard]] Security::Aead::Api::AssociatedData MakeAssociatedData()
        {
            return Security::Aead::Api::AssociatedData{
                .Value = {
                    std::byte{'l'}, std::byte{'e'}, std::byte{'a'},
                    std::byte{'s'}, std::byte{'e'}, std::byte{'-'}, std::byte{'1'}}};
        }
    }

    TEST(ClientTest, SubmitAcquiresLeaseAndSendsAuthenticatedCommand)
    {
        StrictMock<Lease::Api::ILeaseIssuerMock> leaseIssuer;
        StrictMock<::PiSubmarine::Control::ISerializerMock> serializer;
        StrictMock<Security::Aead::Api::IProviderMock> aeadProvider;
        StrictMock<Security::Nonce::Api::IProviderMock> nonceProvider;
        StrictMock<::PiSubmarine::Udp::Api::ISenderMock> sender;

        auto now = std::chrono::steady_clock::time_point{};
        Client client(
            leaseIssuer,
            serializer,
            aeadProvider,
            nonceProvider,
            sender,
            ::PiSubmarine::Udp::Api::Endpoint{"127.0.0.1", 9000},
            [&now] { return now; });

        Api::Input::OperatorCommand inputCommand{};
        Api::Input::OperatorCommand serializedCommand{};
        serializedCommand.LeaseId = Lease::Api::LeaseId{.Value = "lease-1"};

        EXPECT_CALL(leaseIssuer, AcquireLease(Lease::Api::LeaseRequest{
                        .Resource = Lease::Api::ResourceId{.Value = "control-main"}}))
            .WillOnce(Return(Error::Api::Result<Lease::Api::LeaseGrant>(MakeLeaseGrant())));
        EXPECT_CALL(serializer, Serialize(serializedCommand))
            .WillOnce(Return(Error::Api::Result<std::vector<std::byte>>(
                std::vector<std::byte>{std::byte{0x01}, std::byte{0x02}})));
        EXPECT_CALL(nonceProvider, Next())
            .WillOnce(Return(Error::Api::Result<Security::Nonce::Api::Nonce>(
                Security::Nonce::Api::Nonce{.Value = {std::byte{0x10}}})));
        EXPECT_CALL(aeadProvider, Seal(
                        MakeKey(),
                        Security::Nonce::Api::Nonce{.Value = {std::byte{0x10}}},
                        Security::Aead::Api::Plaintext{.Value = {std::byte{0x01}, std::byte{0x02}}},
                        MakeAssociatedData()))
            .WillOnce(Return(Error::Api::Result<Security::Aead::Api::Ciphertext>(
                Security::Aead::Api::Ciphertext{.Value = {std::byte{0x20}}})));
        EXPECT_CALL(sender, Send(::testing::Truly([](const ::PiSubmarine::Udp::Api::Datagram& datagram)
            {
                return datagram.Peer == ::PiSubmarine::Udp::Api::Endpoint{"127.0.0.1", 9000}
                    && datagram.Payload == EncodePacket("lease-1", {std::byte{0x10}}, {std::byte{0x20}});
            })))
            .WillOnce(Return(Error::Api::Result<void>{}));
        EXPECT_CALL(leaseIssuer, ReleaseLease(Lease::Api::LeaseId{.Value = "lease-1"}))
            .WillOnce(Return(Error::Api::Result<void>{}));

        ASSERT_TRUE(client.Submit(inputCommand).has_value());
    }

    TEST(ClientTest, SubmitRenewsLeaseBeforeSendingWhenRenewTimeHasPassed)
    {
        StrictMock<Lease::Api::ILeaseIssuerMock> leaseIssuer;
        StrictMock<::PiSubmarine::Control::ISerializerMock> serializer;
        StrictMock<Security::Aead::Api::IProviderMock> aeadProvider;
        StrictMock<Security::Nonce::Api::IProviderMock> nonceProvider;
        StrictMock<::PiSubmarine::Udp::Api::ISenderMock> sender;

        auto now = std::chrono::steady_clock::time_point{};
        Client client(
            leaseIssuer,
            serializer,
            aeadProvider,
            nonceProvider,
            sender,
            ::PiSubmarine::Udp::Api::Endpoint{"127.0.0.1", 9000},
            [&now] { return now; });

        Api::Input::OperatorCommand inputCommand{};
        Api::Input::OperatorCommand serializedCommand{};
        serializedCommand.LeaseId = Lease::Api::LeaseId{.Value = "lease-1"};

        EXPECT_CALL(leaseIssuer, AcquireLease(_))
            .WillOnce(Return(Error::Api::Result<Lease::Api::LeaseGrant>(MakeLeaseGrant())));
        EXPECT_CALL(serializer, Serialize(serializedCommand))
            .Times(2)
            .WillRepeatedly(Return(Error::Api::Result<std::vector<std::byte>>(
                std::vector<std::byte>{std::byte{0x01}})));
        EXPECT_CALL(nonceProvider, Next())
            .Times(2)
            .WillRepeatedly(Return(Error::Api::Result<Security::Nonce::Api::Nonce>(
                Security::Nonce::Api::Nonce{.Value = {std::byte{0x10}}})));
        EXPECT_CALL(aeadProvider, Seal(_, _, _, _))
            .Times(2)
            .WillRepeatedly(Return(Error::Api::Result<Security::Aead::Api::Ciphertext>(
                Security::Aead::Api::Ciphertext{.Value = {std::byte{0x20}}})));
        EXPECT_CALL(sender, Send(_))
            .Times(2)
            .WillRepeatedly(Return(Error::Api::Result<void>{}));
        EXPECT_CALL(leaseIssuer, RenewLease(Lease::Api::LeaseId{.Value = "lease-1"}))
            .WillOnce(Return(Error::Api::Result<Lease::Api::Lease>(MakeLeaseGrant().Lease)));
        EXPECT_CALL(leaseIssuer, ReleaseLease(Lease::Api::LeaseId{.Value = "lease-1"}))
            .WillOnce(Return(Error::Api::Result<void>{}));

        ASSERT_TRUE(client.Submit(inputCommand).has_value());
        now += std::chrono::milliseconds(2000);
        ASSERT_TRUE(client.Submit(inputCommand).has_value());
    }
}
