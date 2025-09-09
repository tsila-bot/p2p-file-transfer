'use client'

import { useState } from 'react'
import { useRouter } from 'next/navigation'

export default function HomePage() {
  const router = useRouter()

  return (
    <div className="min-h-screen bg-gradient-to-br from-blue-50 to-indigo-100">
      <div className="container mx-auto px-4 py-16">
        <div className="text-center mb-16">
          <h1 className="text-5xl font-bold text-gray-900 mb-6">
            Transfert de Fichiers <span className="text-blue-600">P2P</span>
          </h1>
          <p className="text-xl text-gray-600 max-w-3xl mx-auto mb-8">
            Transférez vos fichiers volumineux de manière sécurisée, 
            directement entre pairs, sans limite de taille.
          </p>
          <div className="space-x-4">
            <button 
              onClick={() => router.push('/auth/register')}
              className="bg-blue-600 hover:bg-blue-700 text-white px-8 py-3 rounded-lg text-lg font-semibold"
            >
              Commencer Maintenant
            </button>
            <button 
              onClick={() => router.push('/auth/login')}
              className="bg-white hover:bg-gray-50 text-blue-600 border border-blue-600 px-8 py-3 rounded-lg text-lg font-semibold"
            >
              Se Connecter
            </button>
          </div>
        </div>
      </div>
    </div>
  )
}
