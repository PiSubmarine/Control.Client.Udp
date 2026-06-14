#include "PiSubmarine/Control/Client/Udp/Client.h"

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <utility>
#include <vector>

namespace PiSubmarine::Control::Client::Udp
{
    namespace
    {
        constexpr std::size_t EncodedFieldSize = sizeof(std::uint32_t);

        void AppendUInt32BigEndian(std::vector<std::byte>& bytes, const std::uint32_t value)
        {
            bytes.push_back(static_cast<std::byte>((value >> 24U) & 0xFFU));
            bytes.push_back(static_cast<std::byte>((value >> 16U) & 0xFFU));
            bytes.push_back(static_cast<std::byte>((value >> 8U) & 0xFFU));
            bytes.push_back(static_cast<std::byte>(value & 0xFFU));
        }

        [[nodiscard]] std::vector<std::byte> EncodeString(const std::string& value)
        {
            std::vector<std::byte> bytes;
            bytes.reserve(value.size());
            for (const char character : value)
            {
                bytes.push_back(static_cast<std::byte>(character));
            }

            return bytes;
        }

        [[nodiscard]] ::PiSubmarine::Security::Aead::Api::Key MakeKey(const Lease::Api::LeaseSecret& leaseSecret)
        {
            return ::PiSubmarine::Security::Aead::Api::Key{.Value = leaseSecret.Value};
        }

        [[nodiscard]] ::PiSubmarine::Security::Aead::Api::AssociatedData MakeAssociatedData(const Lease::Api::LeaseId& leaseId)
        {
            return ::PiSubmarine::Security::Aead::Api::AssociatedData{.Value = EncodeString(leaseId.Value)};
        }

        [[nodiscard]] std::vector<std::byte> BuildPacket(
            const Lease::Api::LeaseId& leaseId,
            const ::PiSubmarine::Security::Api::Nonce& nonce,
            const ::PiSubmarine::Security::Aead::Api::Ciphertext& ciphertext)
        {
            std::vector<std::byte> bytes;
            bytes.reserve(EncodedFieldSize * 2 + leaseId.Value.size() + nonce.Value.size() + ciphertext.Value.size());

            AppendUInt32BigEndian(bytes, static_cast<std::uint32_t>(leaseId.Value.size()));
            const auto leaseIdBytes = EncodeString(leaseId.Value);
            bytes.insert(bytes.end(), leaseIdBytes.begin(), leaseIdBytes.end());

            AppendUInt32BigEndian(bytes, static_cast<std::uint32_t>(nonce.Value.size()));
            bytes.insert(bytes.end(), nonce.Value.begin(), nonce.Value.end());
            bytes.insert(bytes.end(), ciphertext.Value.begin(), ciphertext.Value.end());

            return bytes;
        }
    }

    Client::Client(
        Lease::Api::ILeaseIssuer& leaseIssuer,
        const ::PiSubmarine::Control::ISerializer& serializer,
        const ::PiSubmarine::Security::Aead::Api::IProvider& aeadProvider,
        ::PiSubmarine::Security::Api::INonceProvider& nonceProvider,
        ::PiSubmarine::Udp::Api::ISender& sender,
        ::PiSubmarine::Udp::Api::Endpoint serverEndpoint,
        Clock clock)
        : m_LeaseIssuer(leaseIssuer)
        , m_Serializer(serializer)
        , m_AeadProvider(aeadProvider)
        , m_NonceProvider(nonceProvider)
        , m_Sender(sender)
        , m_ServerEndpoint(std::move(serverEndpoint))
        , m_Clock(std::move(clock))
    {
    }

    Client::~Client()
    {
        std::scoped_lock lock(m_Mutex);
        ReleaseLeaseLocked();
    }

    Error::Api::Result<void> Client::Submit(const Api::Input::OperatorCommand& command)
    {
        std::scoped_lock lock(m_Mutex);

        const auto now = m_Clock();
        if (const auto ensureLeaseResult = EnsureLeaseLocked(now); !ensureLeaseResult.has_value())
        {
            return std::unexpected(ensureLeaseResult.error());
        }

        Api::Input::OperatorCommand commandWithLease = command;
        commandWithLease.LeaseId = m_Lease->Id;

        const auto serializedResult = m_Serializer.Serialize(commandWithLease);
        if (!serializedResult.has_value())
        {
            return std::unexpected(serializedResult.error());
        }

        const auto nonceResult = m_NonceProvider.Next();
        if (!nonceResult.has_value())
        {
            return std::unexpected(nonceResult.error());
        }

        const auto ciphertextResult = m_AeadProvider.Seal(
            MakeKey(*m_LeaseSecret),
            *nonceResult,
            ::PiSubmarine::Security::Aead::Api::Plaintext{.Value = *serializedResult},
            MakeAssociatedData(m_Lease->Id));
        if (!ciphertextResult.has_value())
        {
            return std::unexpected(ciphertextResult.error());
        }

        return m_Sender.Send(::PiSubmarine::Udp::Api::Datagram{
            .Peer = m_ServerEndpoint,
            .Payload = BuildPacket(m_Lease->Id, *nonceResult, *ciphertextResult)});
    }

    Lease::Api::ResourceId Client::MakeControlResourceId()
    {
        return Lease::Api::ResourceId{.Value = "control-main"};
    }

    std::chrono::steady_clock::duration Client::ComputeRenewInterval(const Lease::Api::Lease& lease)
    {
        const auto halfDuration = lease.Duration / 2;
        const auto boundedDuration = std::max(halfDuration, std::chrono::milliseconds(1));
        return boundedDuration;
    }

    Error::Api::Result<void> Client::EnsureLeaseLocked(const TimePoint& now)
    {
        if (m_Lease.has_value() && m_LeaseSecret.has_value())
        {
            if (now < m_NextRenewAt)
            {
                return {};
            }

            const auto renewResult = m_LeaseIssuer.RenewLease(m_Lease->Id);
            if (renewResult.has_value())
            {
                m_Lease = *renewResult;
                m_NextRenewAt = now + ComputeRenewInterval(*m_Lease);
                return {};
            }

            ReleaseLeaseLocked();
        }

        const auto acquireResult = m_LeaseIssuer.AcquireLease(Lease::Api::LeaseRequest{
            .Resource = MakeControlResourceId()});
        if (!acquireResult.has_value())
        {
            return std::unexpected(acquireResult.error());
        }

        m_Lease = acquireResult->Lease;
        m_LeaseSecret = acquireResult->Secret;
        m_NextRenewAt = now + ComputeRenewInterval(*m_Lease);
        return {};
    }

    void Client::ReleaseLeaseLocked() noexcept
    {
        if (m_Lease.has_value())
        {
            [[maybe_unused]] const auto releaseResult = m_LeaseIssuer.ReleaseLease(m_Lease->Id);
        }

        m_Lease.reset();
        m_LeaseSecret.reset();
        m_NextRenewAt = TimePoint{};
    }
}
