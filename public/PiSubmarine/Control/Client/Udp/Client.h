#pragma once

#include <chrono>
#include <functional>
#include <mutex>
#include <optional>

#include "PiSubmarine/Control/Api/Input/ISink.h"
#include "PiSubmarine/Control/ISerializer.h"
#include "PiSubmarine/Lease/Api/ILeaseIssuer.h"
#include "PiSubmarine/Security/Api/INonceProvider.h"
#include "PiSubmarine/Security/Aead/Api/IProvider.h"
#include "PiSubmarine/Udp/Api/ISender.h"

namespace PiSubmarine::Control::Client::Udp
{
    class Client final : public Api::Input::ISink
    {
    public:
        using TimePoint = std::chrono::steady_clock::time_point;
        using Clock = std::function<TimePoint()>;

        Client(
            Lease::Api::ILeaseIssuer& leaseIssuer,
            const ::PiSubmarine::Control::ISerializer& serializer,
            const ::PiSubmarine::Security::Aead::Api::IProvider& aeadProvider,
            ::PiSubmarine::Security::Api::INonceProvider& nonceProvider,
            ::PiSubmarine::Udp::Api::ISender& sender,
            ::PiSubmarine::Udp::Api::Endpoint serverEndpoint,
            Clock clock = [] { return std::chrono::steady_clock::now(); });

        ~Client() override;

        [[nodiscard]] bool HasLease() const noexcept;
        [[nodiscard]] Error::Api::Result<void> Submit(const Api::Input::OperatorCommand& command) override;

    private:
        [[nodiscard]] static Lease::Api::ResourceId MakeControlResourceId();
        [[nodiscard]] static std::chrono::steady_clock::duration ComputeRenewInterval(const Lease::Api::Lease& lease);
        [[nodiscard]] Error::Api::Result<void> EnsureLeaseLocked(const TimePoint& now);
        void ReleaseLeaseLocked() noexcept;

        Lease::Api::ILeaseIssuer& m_LeaseIssuer;
        const ::PiSubmarine::Control::ISerializer& m_Serializer;
        const ::PiSubmarine::Security::Aead::Api::IProvider& m_AeadProvider;
        ::PiSubmarine::Security::Api::INonceProvider& m_NonceProvider;
        ::PiSubmarine::Udp::Api::ISender& m_Sender;
        ::PiSubmarine::Udp::Api::Endpoint m_ServerEndpoint;
        Clock m_Clock;

        std::mutex m_Mutex;
        std::optional<Lease::Api::Lease> m_Lease;
        std::optional<Lease::Api::LeaseSecret> m_LeaseSecret;
        TimePoint m_NextRenewAt{};
    };
}
