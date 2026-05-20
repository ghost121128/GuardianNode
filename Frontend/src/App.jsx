import React, {
  useState,
  useEffect,
} from "react";

import {
  Routes,
  Route,
  Navigate,
} from "react-router-dom";

import Dashboard from "./pages/Dashboard";
import ThreatFeed from "./pages/ThreatFeed";
import Analytics from "./pages/Analytics";
import Reports from "./pages/Reports";
import Settings from "./pages/Settings";
import Login from "./pages/Login";

import Sidebar from "./components/ui/Sidebar";
import BottomNav from "./components/ui/BottomNav";

// =========================
// Protected Layout
// =========================

const ProtectedLayout = ({

  children,
  darkMode,
  setDarkMode,

}) => {

  const isAuth =
    localStorage.getItem(
      "guardian_auth"
    );

  if (!isAuth) {

    return <Navigate to="/" />;

  }

  return (

    <div className={`flex min-h-screen transition-all duration-500 ${
      darkMode

        ? "bg-[#040816] text-white"

        : "bg-white text-black"
    }`}>

      {/* Desktop Sidebar */}

      <div className="hidden md:block">

        <Sidebar
          darkMode={darkMode}
          setDarkMode={setDarkMode}
        />

      </div>

      {/* Main Content */}

      <div className="flex-1 overflow-auto">

        {children}

      </div>

      {/* Mobile Bottom Navigation */}

      <BottomNav
        darkMode={darkMode}
      />

    </div>

  );

};

// =========================
// App
// =========================

function App() {

  // =========================
  // Global Theme State
  // =========================

  const [darkMode, setDarkMode] =
    useState(() => {

      const savedTheme =
        localStorage.getItem(
          "guardian_theme"
        );

      return savedTheme !== "light";

    });

  // =========================
  // Save Theme
  // =========================

  useEffect(() => {

    localStorage.setItem(

      "guardian_theme",

      darkMode
        ? "dark"
        : "light"

    );

  }, [darkMode]);

  return (

    <Routes>

      {/* Login */}

      <Route
        path="/"
        element={<Login />}
      />

      {/* Dashboard */}

      <Route
        path="/dashboard"

        element={

          <ProtectedLayout
            darkMode={darkMode}
            setDarkMode={setDarkMode}
          >

            <Dashboard
              darkMode={darkMode}
              setDarkMode={setDarkMode}
            />

          </ProtectedLayout>

        }
      />

      {/* Threat Feed */}

      <Route
        path="/threat-feed"

        element={

          <ProtectedLayout
            darkMode={darkMode}
            setDarkMode={setDarkMode}
          >

            <ThreatFeed
              darkMode={darkMode}
              setDarkMode={setDarkMode}
            />

          </ProtectedLayout>

        }
      />

      {/* Analytics */}

      <Route
        path="/analytics"

        element={

          <ProtectedLayout
            darkMode={darkMode}
            setDarkMode={setDarkMode}
          >

            <Analytics
              darkMode={darkMode}
              setDarkMode={setDarkMode}
            />

          </ProtectedLayout>

        }
      />

      {/* Reports */}

      <Route
        path="/reports"

        element={

          <ProtectedLayout
            darkMode={darkMode}
            setDarkMode={setDarkMode}
          >

            <Reports
              darkMode={darkMode}
              setDarkMode={setDarkMode}
            />

          </ProtectedLayout>

        }
      />

      {/* Settings */}

      <Route
        path="/settings"

        element={

          <ProtectedLayout
            darkMode={darkMode}
            setDarkMode={setDarkMode}
          >

            <Settings
              darkMode={darkMode}
              setDarkMode={setDarkMode}
            />

          </ProtectedLayout>

        }
      />

    </Routes>

  );

}

export default App;