import { useState } from "react"
import { useNavigate } from "react-router-dom"

export default function Login() {

  const navigate = useNavigate()

  const [email, setEmail] = useState("")
  const [password, setPassword] = useState("")

  const handleLogin = async (e) => {
    e.preventDefault()

    try {

      const response = await fetch(
        "http://127.0.0.1:5000/api/auth/login",
        {
          method: "POST",
          headers: {
            "Content-Type": "application/json",
          },
          body: JSON.stringify({
            email,
            password,
          }),
        }
      )

      const data = await response.json()

      if (response.ok) {

        localStorage.setItem(
          "token",
          data.token
        )

        localStorage.setItem(
          "user",
          JSON.stringify(data.user)
        )

        navigate("/dashboard")

      } else {

        alert(data.message)
      }

    } catch (error) {

      console.error(error)

      alert("Server error")
    }
  }

  return (
    <div className="min-h-screen flex items-center justify-center bg-[#050816]">

      <form
        onSubmit={handleLogin}
        className="w-full max-w-md bg-white/5 border border-white/10 rounded-3xl p-8 backdrop-blur-xl"
      >

        <h1 className="text-4xl font-black text-white mb-8">
          Login
        </h1>

        <input
          type="email"
          placeholder="Email"
          value={email}
          onChange={(e) => setEmail(e.target.value)}
          className="w-full mb-4 p-4 rounded-xl bg-black/30 border border-white/10 text-white outline-none"
        />

        <input
          type="password"
          placeholder="Password"
          value={password}
          onChange={(e) => setPassword(e.target.value)}
          className="w-full mb-6 p-4 rounded-xl bg-black/30 border border-white/10 text-white outline-none"
        />

        <button
          type="submit"
          className="w-full py-4 rounded-xl bg-cyan-500 hover:bg-cyan-400 transition-all text-black font-bold"
        >
          Login
        </button>

      </form>
    </div>
  )
}