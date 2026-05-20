import { useState } from "react"
import { useNavigate } from "react-router-dom"

export default function Register() {

  const navigate = useNavigate()

  const [name, setName] = useState("")
  const [email, setEmail] = useState("")
  const [password, setPassword] = useState("")

  const handleRegister = async (e) => {
    e.preventDefault()

    try {

      const response = await fetch(
        "https://your-render-url.onrender.com/api/auth/register",
        {
          method: "POST",
          headers: {
            "Content-Type": "application/json",
          },
          body: JSON.stringify({
            name,
            email,
            password,
          }),
        }
      )

      const data = await response.json()

      if (response.ok) {

        alert("Registration successful")

        navigate("/login")

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
        onSubmit={handleRegister}
        className="w-full max-w-md bg-white/5 border border-white/10 rounded-3xl p-8 backdrop-blur-xl"
      >

        <h1 className="text-4xl font-black text-white mb-8">
          Register
        </h1>

        <input
          type="text"
          placeholder="Name"
          value={name}
          onChange={(e) => setName(e.target.value)}
          className="w-full mb-4 p-4 rounded-xl bg-black/30 border border-white/10 text-white outline-none"
        />

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
          className="w-full py-4 rounded-xl bg-purple-500 hover:bg-purple-400 transition-all text-white font-bold"
        >
          Register
        </button>

      </form>
    </div>
  )
}