import React from "react";

import {

  LayoutDashboard,

  ShieldAlert,

  BarChart3,

  FileText,

  Settings,

} from "lucide-react";

import {
  NavLink,
  useNavigate,
} from "react-router-dom";

const Sidebar = ({

  darkMode,

  setDarkMode,

}) => {

  const navigate =
    useNavigate();

  const isMobile =
    window.innerWidth < 768;

  const menuItems = [

    {

      name: "Dashboard",

      icon: LayoutDashboard,

      path: "/dashboard",

    },

    {

      name: "Threat Feed",

      icon: ShieldAlert,

      path: "/threat-feed",

    },

    {

      name: "Analytics",

      icon: BarChart3,

      path: "/analytics",

    },

    {

      name: "Reports",

      icon: FileText,

      path: "/reports",

    },

    {

      name: "Settings",

      icon: Settings,

      path: "/settings",

    },

  ];

  const handleLogout = () => {

    localStorage.removeItem(
      "guardian_auth"
    );

    navigate("/");

  };

  return (

    <div className={`${
      isMobile

        ? "w-[85px]"

        : "w-[300px]"

    } h-screen sticky top-0 border-r transition-all duration-500 flex flex-col justify-between overflow-hidden ${
      darkMode

        ? "bg-[#050b1a] border-white/10 text-white"

        : "bg-[#f4f7fb] border-black/10 text-black"
    }`}>

      {/* Top */}

      <div className="overflow-y-auto">

        {/* Logo */}

        <div className="p-5 md:p-8">

          <h1 className={`font-black text-cyan-400 ${
            isMobile

              ? "text-lg"

              : "text-4xl"
          }`}>

            GuardianNode

          </h1>

          <p className={`mt-2 ${
            isMobile

              ? "hidden"

              :

            darkMode

              ? "text-gray-400"

              : "text-gray-600"
          }`}>

            Cyber Defense Platform

          </p>

        </div>

        {/* Navigation */}

        <div className="px-3 md:px-4 space-y-3">

          {

            menuItems.map(
              (
                item,
                index
              ) => {

                const Icon =
                  item.icon;

                return (

                  <NavLink

                    key={index}

                    to={item.path}

                    className={({

                      isActive,

                    }) => `flex items-center ${
                      isMobile

                        ? "justify-center"

                        : "gap-4"
                    } px-4 py-4 rounded-2xl transition-all duration-300 ${
                      isActive

                        ?

                        darkMode

                          ?

                          "bg-cyan-500/20 border border-cyan-500/20 text-cyan-400"

                          :

                          "bg-cyan-100 text-cyan-700 border border-cyan-200"

                        :

                        darkMode

                          ?

                          "hover:bg-white/5"

                          :

                          "hover:bg-black/5"
                    }`}
                  >

                    <Icon size={22} />

                    <span className={`font-semibold ${
                      isMobile

                        ? "hidden"

                        : "block"
                    }`}>

                      {item.name}

                    </span>

                  </NavLink>

                );

              }
            )

          }

        </div>

      </div>

      {/* Bottom */}

      <div className="p-4 md:p-6 border-t border-white/5">

        {/* Theme Switch */}

        <div className="w-full flex items-center justify-center mb-6">

          <label className="switch">

            <input

              type="checkbox"

              checked={!darkMode}

              onChange={() =>
                setDarkMode(
                  !darkMode
                )
              }

            />

            <span className="slider">

              <span className="star star_1"></span>

              <span className="star star_2"></span>

              <span className="star star_3"></span>

              <svg
                viewBox="0 0 16 16"
                className="cloud"
                fill="currentColor"
                height="40"
                width="40"
                xmlns="http://www.w3.org/2000/svg"
              >

                <path
                  transform="matrix(.77976 0 0 .78395-299.99-418.63)"
                  fill="#fff"
                  d="m587.75 543.09c-2.3914 0-4.4641 1.3756-5.4785 3.3808-0.34116-0.0789-0.69525-0.121-1.0596-0.121-2.6602 0-4.8105 2.1504-4.8105 4.8105 0 2.6602 2.1504 4.8105 4.8105 4.8105h12.041c2.6602 0 4.8105-2.1504 4.8105-4.8105 0-2.6602-2.1504-4.8105-4.8105-4.8105-0.36432 0-0.71843 0.0421-1.0596 0.121-1.0144-2.0052-3.0871-3.3808-5.4785-3.3808z"
                />

              </svg>

            </span>

          </label>

        </div>

        {/* Logout */}

        <button

          onClick={handleLogout}

          className={`w-full rounded-2xl bg-red-500/10 border border-red-500/20 text-red-400 py-4 font-bold transition-all duration-300 hover:bg-red-500/20 ${
            isMobile

              ? "px-2 text-xs"

              : "px-5"
          }`}
        >

          {

            isMobile

              ? "⎋"

              : "Logout"

          }

        </button>

      </div>

    </div>

  );

};

export default Sidebar;