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
} from "react-router-dom";

const BottomNav = ({

  darkMode,

}) => {

  const menuItems = [

    {

      name: "Dashboard",

      icon: LayoutDashboard,

      path: "/dashboard",

    },

    {

      name: "Threats",

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

  return (

    <div className={`fixed bottom-4 left-1/2 -translate-x-1/2 z-[999] md:hidden backdrop-blur-2xl border rounded-[30px] px-2 py-2 shadow-2xl flex items-center justify-between gap-1 transition-all duration-500 ${
      darkMode

        ? "bg-[#081120]/80 border-cyan-500/10"

        : "bg-white/90 border-gray-200"
    }`}>

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

                }) => `flex flex-col items-center justify-center px-4 py-3 rounded-2xl transition-all duration-300 ${
                  isActive

                    ?

                    darkMode

                      ?

                      "bg-cyan-500/20 text-cyan-400 shadow-lg shadow-cyan-500/10"

                      :

                      "bg-cyan-100 text-cyan-700"

                    :

                    darkMode

                      ?

                      "text-gray-400 hover:text-white"

                      :

                      "text-gray-500 hover:text-black"
                }`}
              >

                <Icon size={20} />

                <span className="text-[10px] mt-1 font-semibold">

                  {item.name}

                </span>

              </NavLink>

            );

          }
        )

      }

    </div>

  );

};

export default BottomNav;