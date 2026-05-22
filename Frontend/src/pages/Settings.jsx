import {
  Shield,
  Bell,
  Moon,
  Lock,
  Database,
  Save,
} from "lucide-react";

const Settings = ({

  darkMode,
  setDarkMode,

}) => {

  return (

    <div className={`min-h-screen w-full overflow-x-hidden p-4 sm:p-6 md:p-8 pb-28 md:pb-8 transition-all duration-500 ${
      darkMode

        ? "bg-[#040816] text-white"

        : "bg-white text-gray-900"
    }`}>

      {/* Header */}

      <div className="mb-10">

        <h1 className="text-3xl sm:text-4xl md:text-5xl font-black mb-2 break-words">

          Settings

        </h1>

        <p className={`text-sm sm:text-base leading-relaxed ${
          darkMode

            ? "text-gray-400"

            : "text-gray-500"
        }`}>

          Configure GuardianNode preferences and security settings

        </p>

      </div>

      {/* Settings Grid */}

      <div className="grid grid-cols-1 xl:grid-cols-2 gap-6 md:gap-8">

        {/* Appearance */}

        <div className={`backdrop-blur-xl border rounded-[28px] md:rounded-[32px] p-5 sm:p-6 md:p-8 shadow-xl overflow-hidden ${
          darkMode

            ? "bg-[#0B1120]/80 border-[#1E293B]"

            : "bg-gray-100 border-gray-200"
        }`}>

          <div className="flex items-start sm:items-center gap-4 mb-6">

            <div className="bg-cyan-500/10 p-3 md:p-4 rounded-2xl shrink-0">

              <Moon className="text-cyan-400" />

            </div>

            <div className="min-w-0">

              <h2 className="text-2xl sm:text-3xl font-black break-words">

                Appearance

              </h2>

              <p className={`text-sm sm:text-base break-words ${
                darkMode

                  ? "text-gray-400"

                  : "text-gray-500"
              }`}>

                Customize dashboard theme

              </p>

            </div>

          </div>

          <button

            onClick={() =>
              setDarkMode(!darkMode)
            }

            className="bg-cyan-500 hover:bg-cyan-400 text-black font-bold px-5 sm:px-6 py-3 rounded-2xl transition-all duration-300 w-full sm:w-fit text-sm sm:text-base"
          >

            Switch to {

              darkMode
                ? "Light"
                : "Dark"

            } Mode

          </button>

        </div>

        {/* Notifications */}

        <div className={`backdrop-blur-xl border rounded-[28px] md:rounded-[32px] p-5 sm:p-6 md:p-8 shadow-xl overflow-hidden ${
          darkMode

            ? "bg-[#0B1120]/80 border-[#1E293B]"

            : "bg-gray-100 border-gray-200"
        }`}>

          <div className="flex items-start sm:items-center gap-4 mb-6">

            <div className="bg-yellow-500/10 p-3 md:p-4 rounded-2xl shrink-0">

              <Bell className="text-yellow-400" />

            </div>

            <div className="min-w-0">

              <h2 className="text-2xl sm:text-3xl font-black break-words">

                Notifications

              </h2>

              <p className={`text-sm sm:text-base break-words ${
                darkMode

                  ? "text-gray-400"

                  : "text-gray-500"
              }`}>

                Threat alert preferences

              </p>

            </div>

          </div>

          <div className="space-y-4">

            {[
              "Email Alerts",
              "SMS Notifications",
              "Live Threat Alerts",
            ].map((item, index) => (

              <div
                key={index}

                className={`flex items-center justify-between gap-4 rounded-2xl px-4 sm:px-5 py-4 border ${
                  darkMode

                    ? "bg-[#111827] border-[#1E293B]"

                    : "bg-white border-gray-200"
                }`}
              >

                <span className="text-sm sm:text-base break-words">

                  {item}

                </span>

                <div className="w-12 h-6 bg-cyan-500 rounded-full flex items-center px-1 shrink-0">

                  <div className="w-4 h-4 bg-white rounded-full ml-auto" />

                </div>

              </div>

            ))}

          </div>

        </div>

        {/* Security */}

        <div className={`backdrop-blur-xl border rounded-[28px] md:rounded-[32px] p-5 sm:p-6 md:p-8 shadow-xl overflow-hidden ${
          darkMode

            ? "bg-[#0B1120]/80 border-[#1E293B]"

            : "bg-gray-100 border-gray-200"
        }`}>

          <div className="flex items-start sm:items-center gap-4 mb-6">

            <div className="bg-red-500/10 p-3 md:p-4 rounded-2xl shrink-0">

              <Shield className="text-red-400" />

            </div>

            <div className="min-w-0">

              <h2 className="text-2xl sm:text-3xl font-black break-words">

                Security

              </h2>

              <p className={`text-sm sm:text-base break-words ${
                darkMode

                  ? "text-gray-400"

                  : "text-gray-500"
              }`}>

                Access and protection settings

              </p>

            </div>

          </div>

          <div className="space-y-4">

            <div className={`rounded-2xl px-4 sm:px-5 py-4 flex items-start sm:items-center gap-4 border break-words ${
              darkMode

                ? "bg-[#111827] border-[#1E293B]"

                : "bg-white border-gray-200"
            }`}>

              <Lock className="text-cyan-400 shrink-0" />

              <span className="break-words">

                Two-Factor Authentication Enabled

              </span>

            </div>

            <div className={`rounded-2xl px-4 sm:px-5 py-4 flex items-start sm:items-center gap-4 border break-words ${
              darkMode

                ? "bg-[#111827] border-[#1E293B]"

                : "bg-white border-gray-200"
            }`}>

              <Database className="text-green-400 shrink-0" />

              <span className="break-words">

                Encrypted Threat Database Active

              </span>

            </div>

          </div>

        </div>

        {/* Save Panel */}

        <div className={`backdrop-blur-xl border rounded-[28px] md:rounded-[32px] p-5 sm:p-6 md:p-8 shadow-xl flex flex-col justify-between overflow-hidden ${
          darkMode

            ? "bg-[#0B1120]/80 border-[#1E293B]"

            : "bg-gray-100 border-gray-200"
        }`}>

          <div>

            <h2 className="text-2xl sm:text-3xl font-black mb-4 break-words">

              Save Configuration

            </h2>

            <p className={`mb-8 text-sm sm:text-base leading-relaxed ${
              darkMode

                ? "text-gray-400"

                : "text-gray-500"
            }`}>

              Save all dashboard configuration changes securely.

            </p>

          </div>

          <button
            className="bg-cyan-500 hover:bg-cyan-400 text-black font-bold px-6 py-4 rounded-2xl transition-all duration-300 flex items-center justify-center gap-3 w-full text-sm sm:text-base"
          >

            <Save size={20} />

            Save Settings

          </button>

        </div>

      </div>

    </div>

  );

};

export default Settings;