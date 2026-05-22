import {
  Shield,
  Lock,
  User,
} from "lucide-react";

import {
  useState,
} from "react";

import {
  useNavigate,
} from "react-router-dom";

const Login = () => {

  const navigate = useNavigate();

  const [username, setUsername] =
    useState("");

  const [password, setPassword] =
    useState("");

  const handleLogin = (e) => {

    e.preventDefault();

    console.log("Username:", username);
    console.log("Password:", password);

    if (
      username.trim() === "admin" &&
      password.trim() === "admin123"
    ) {

      localStorage.setItem(
        "guardian_auth",
        "true"
      );

      navigate("/dashboard");

    }

    else {

      alert(
        "Invalid Credentials"
      );

    }

  };

  return (

    <div className="min-h-screen w-full overflow-x-hidden bg-[#040816] flex items-center justify-center px-4 py-8 sm:px-6 md:px-8">

      <div className="w-full max-w-md bg-[#0B1120]/80 backdrop-blur-xl border border-[#1E293B] rounded-[28px] sm:rounded-[40px] p-6 sm:p-8 md:p-10 shadow-2xl">

        {/* Logo */}

        <div className="text-center mb-8 md:mb-10">

          <div className="w-16 h-16 sm:w-20 sm:h-20 rounded-full bg-cyan-500/10 flex items-center justify-center mx-auto mb-5 md:mb-6">

            <Shield
              size={32}
              className="text-cyan-400 sm:w-10 sm:h-10"
            />

          </div>

          <h1 className="text-3xl sm:text-4xl md:text-5xl font-black text-white mb-3 break-words">

            GuardianNode

          </h1>

          <p className="text-gray-400 text-sm sm:text-base">

            Enterprise Cybersecurity Access

          </p>

        </div>

        {/* Form */}

        <form
          onSubmit={handleLogin}
          className="space-y-5 sm:space-y-6"
        >

          {/* Username */}

          <div>

            <label className="text-sm text-gray-400 mb-3 block">

              Username

            </label>

            <div className="bg-[#111827] border border-[#1E293B] rounded-2xl px-4 sm:px-5 py-3 sm:py-4 flex items-center gap-3 sm:gap-4">

              <User className="text-cyan-400 shrink-0" />

              <input
                type="text"
                placeholder="Enter username"

                value={username}

                onChange={(e) =>
                  setUsername(
                    e.target.value
                  )
                }

                className="bg-transparent outline-none w-full text-white text-sm sm:text-base"
              />

            </div>

          </div>

          {/* Password */}

          <div>

            <label className="text-sm text-gray-400 mb-3 block">

              Password

            </label>

            <div className="bg-[#111827] border border-[#1E293B] rounded-2xl px-4 sm:px-5 py-3 sm:py-4 flex items-center gap-3 sm:gap-4">

              <Lock className="text-cyan-400 shrink-0" />

              <input
                type="password"
                placeholder="Enter password"

                value={password}

                onChange={(e) =>
                  setPassword(
                    e.target.value
                  )
                }

                className="bg-transparent outline-none w-full text-white text-sm sm:text-base"
              />

            </div>

          </div>

          {/* Button */}

          <button
            type="submit"

            className="w-full bg-cyan-500 hover:bg-cyan-400 text-black font-black py-3 sm:py-4 rounded-2xl transition-all duration-300 text-base sm:text-lg"
          >

            ACCESS DASHBOARD

          </button>

        </form>

        {/* Demo Credentials */}

        <div className="mt-6 sm:mt-8 text-center">

          <p className="text-gray-400 text-xs sm:text-sm leading-relaxed">

            Demo Login:
            {" "}
            <span className="text-cyan-400 break-all">

              admin / admin123

            </span>

          </p>

        </div>

      </div>

    </div>

  );

};

export default Login;