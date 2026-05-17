import {
  User,
  Bell,
  Shield,
  KeyRound,
  Save,
} from "lucide-react";

const Settings = () => {
  return (
    <div className="min-h-screen bg-[#050816] text-white p-8">

      {/* Header */}
      <div className="mb-10">

        <h1 className="text-5xl font-bold mb-2">
          Settings
        </h1>

        <p className="text-gray-400 text-lg">
          Configure your GuardianNode environment
        </p>

      </div>

      <div className="grid lg:grid-cols-2 gap-8">

        {/* Profile Settings */}
        <div className="bg-[#0B1120] border border-gray-800 rounded-3xl p-6">

          <div className="flex items-center gap-3 mb-6">

            <User className="text-cyan-400" />

            <h2 className="text-2xl font-bold">
              Profile Settings
            </h2>

          </div>

          <div className="space-y-5">

            <div>
              <label className="block mb-2 text-gray-400">
                Full Name
              </label>

              <input
                type="text"
                placeholder="Kalpesh Hirudkar"
                className="w-full bg-[#111827] border border-gray-700 rounded-2xl px-4 py-3 outline-none focus:border-cyan-500"
              />
            </div>

            <div>
              <label className="block mb-2 text-gray-400">
                Email Address
              </label>

              <input
                type="email"
                placeholder="guardian@node.com"
                className="w-full bg-[#111827] border border-gray-700 rounded-2xl px-4 py-3 outline-none focus:border-cyan-500"
              />
            </div>

            <button className="bg-cyan-500 hover:bg-cyan-400 transition-all duration-300 text-black font-semibold px-5 py-3 rounded-2xl flex items-center gap-2">

              <Save size={18} />

              Save Changes

            </button>

          </div>

        </div>

        {/* Notification Settings */}
        <div className="bg-[#0B1120] border border-gray-800 rounded-3xl p-6">

          <div className="flex items-center gap-3 mb-6">

            <Bell className="text-yellow-400" />

            <h2 className="text-2xl font-bold">
              Notification Settings
            </h2>

          </div>

          <div className="space-y-5">

            {[
              "Email Notifications",
              "Critical Threat Alerts",
              "Weekly Security Reports",
              "Live Threat Detection",
            ].map((setting, index) => (

              <div
                key={index}
                className="flex justify-between items-center bg-[#111827] border border-gray-800 rounded-2xl p-4"
              >

                <span className="font-medium">
                  {setting}
                </span>

                <div className="w-14 h-7 bg-cyan-500 rounded-full flex items-center px-1">

                  <div className="w-5 h-5 bg-white rounded-full ml-auto" />

                </div>

              </div>

            ))}

          </div>

        </div>

        {/* Security Settings */}
        <div className="bg-[#0B1120] border border-gray-800 rounded-3xl p-6">

          <div className="flex items-center gap-3 mb-6">

            <Shield className="text-green-400" />

            <h2 className="text-2xl font-bold">
              Security Settings
            </h2>

          </div>

          <div className="space-y-5">

            <div className="bg-[#111827] border border-gray-800 rounded-2xl p-5">

              <p className="text-lg font-semibold mb-2">
                Multi-Factor Authentication
              </p>

              <p className="text-gray-400 mb-4">
                Enhance account protection with MFA
              </p>

              <button className="bg-green-500/20 text-green-400 border border-green-500 px-4 py-2 rounded-xl font-semibold">
                Enabled
              </button>

            </div>

            <div className="bg-[#111827] border border-gray-800 rounded-2xl p-5">

              <p className="text-lg font-semibold mb-2">
                Session Timeout
              </p>

              <p className="text-gray-400">
                Automatic logout after 30 minutes
              </p>

            </div>

          </div>

        </div>

        {/* API Settings */}
        <div className="bg-[#0B1120] border border-gray-800 rounded-3xl p-6">

          <div className="flex items-center gap-3 mb-6">

            <KeyRound className="text-purple-400" />

            <h2 className="text-2xl font-bold">
              API Configuration
            </h2>

          </div>

          <div className="space-y-5">

            <div>
              <label className="block mb-2 text-gray-400">
                API Key
              </label>

              <input
                type="password"
                value="GNODE_2026_SECURE_API"
                readOnly
                className="w-full bg-[#111827] border border-gray-700 rounded-2xl px-4 py-3 outline-none"
              />
            </div>

            <div>
              <label className="block mb-2 text-gray-400">
                Webhook Endpoint
              </label>

              <input
                type="text"
                value="https://guardian-node/api/webhooks"
                readOnly
                className="w-full bg-[#111827] border border-gray-700 rounded-2xl px-4 py-3 outline-none"
              />
            </div>

          </div>

        </div>

      </div>

    </div>
  );
};

export default Settings;