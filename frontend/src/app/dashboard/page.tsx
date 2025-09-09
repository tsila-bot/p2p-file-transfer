'use client'

import { useEffect, useState } from 'react'
import { useRouter } from 'next/navigation'

interface User {
  id: string;
  username: string;
  email: string;
}

interface Peer {
  socketId: string;
  userId: string;
  username: string;
}

export default function DashboardPage() {
  const router = useRouter()
  const [user, setUser] = useState<User | null>(null)
  const [peers, setPeers] = useState<Peer[]>([])
  const [socket, setSocket] = useState<any>(null)

  useEffect(() => {
    // Vérifier l'authentification
    const token = localStorage.getItem('token')
    const userData = localStorage.getItem('user')
    
    if (!token || !userData) {
      router.push('/auth/login')
      return
    }

    setUser(JSON.parse(userData))

    // Connexion Socket.IO
    import('socket.io-client').then(({ io }) => {
      const newSocket = io(`${process.env.NEXT_PUBLIC_WS_URL}`, {
        transports: ['websocket']
      })

      // Authentifier le socket
      newSocket.emit('authenticate', token)

      // Écouter les événements
      newSocket.on('peers-list', (peersList: Peer[]) => {
        setPeers(peersList)
      })

      newSocket.on('peer-online', (peer: Peer) => {
        setPeers(prev => [...prev, peer])
      })

      newSocket.on('peer-offline', (data: { peerId: string }) => {
        setPeers(prev => prev.filter(p => p.socketId !== data.peerId))
      })

      setSocket(newSocket)

      return () => {
        newSocket.disconnect()
      }
    })
  }, [router])

  const handleLogout = () => {
    localStorage.removeItem('token')
    localStorage.removeItem('user')
    router.push('/')
  }

  if (!user) {
    return <div>Chargement...</div>
  }

  return (
    <div className="min-h-screen bg-gray-50">
      <nav className="bg-white shadow">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
          <div className="flex justify-between h-16">
            <div className="flex items-center">
              <h1 className="text-xl font-semibold">P2P File Transfer</h1>
            </div>
            <div className="flex items-center space-x-4">
              <span className="text-gray-700">Bonjour, {user.username}</span>
              <button
                onClick={handleLogout}
                className="bg-red-600 hover:bg-red-700 text-white px-4 py-2 rounded-md text-sm"
              >
                Déconnexion
              </button>
            </div>
          </div>
        </div>
      </nav>

      <main className="max-w-7xl mx-auto py-6 sm:px-6 lg:px-8">
        <div className="px-4 py-6 sm:px-0">
          <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
            {/* Zone de drop de fichiers */}
            <div className="bg-white overflow-hidden shadow rounded-lg">
              <div className="px-4 py-5 sm:p-6">
                <h3 className="text-lg leading-6 font-medium text-gray-900 mb-4">
                  Envoyer un fichier
                </h3>
                <div className="border-2 border-dashed border-gray-300 rounded-lg p-12 text-center">
                  <div className="space-y-2">
                    <svg className="mx-auto h-12 w-12 text-gray-400" stroke="currentColor" fill="none" viewBox="0 0 48 48">
                      <path d="M28 8H12a4 4 0 00-4 4v20m32-12v8m0 0v8a4 4 0 01-4 4H12a4 4 0 01-4-4v-4m32-4l-3.172-3.172a4 4 0 00-5.656 0L28 28M8 32l9.172-9.172a4 4 0 015.656 0L28 28m0 0l4 4m4-24h8m-4-4v8m-12 4h.02" strokeWidth={2} strokeLinecap="round" strokeLinejoin="round" />
                    </svg>
                    <p className="text-gray-600">
                      Glissez-déposez vos fichiers ici ou 
                      <button className="text-blue-600 hover:text-blue-500 ml-1">
                        cliquez pour sélectionner
                      </button>
                    </p>
                  </div>
                </div>
              </div>
            </div>

            {/* Liste des pairs connectés */}
            <div className="bg-white overflow-hidden shadow rounded-lg">
              <div className="px-4 py-5 sm:p-6">
                <h3 className="text-lg leading-6 font-medium text-gray-900 mb-4">
                  Pairs connectés ({peers.length})
                </h3>
                <div className="space-y-3">
                  {peers.length === 0 ? (
                    <p className="text-gray-500 text-center py-4">
                      Aucun pair connecté pour le moment
                    </p>
                  ) : (
                    peers.map((peer) => (
                      <div key={peer.socketId} className="flex items-center justify-between p-3 bg-gray-50 rounded-lg">
                        <div className="flex items-center">
                          <div className="w-3 h-3 bg-green-400 rounded-full mr-3"></div>
                          <span className="font-medium text-gray-900">{peer.username}</span>
                        </div>
                        <button className="bg-blue-600 hover:bg-blue-700 text-white px-3 py-1 rounded text-sm">
                          Connecter
                        </button>
                      </div>
                    ))
                  )}
                </div>
              </div>
            </div>
          </div>

          {/* Statistiques */}
          <div className="mt-6 bg-white overflow-hidden shadow rounded-lg">
            <div className="px-4 py-5 sm:p-6">
              <h3 className="text-lg leading-6 font-medium text-gray-900 mb-4">
                Statistiques
              </h3>
              <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
                <div className="text-center">
                  <div className="text-2xl font-bold text-blue-600">0</div>
                  <div className="text-gray-500">Fichiers envoyés</div>
                </div>
                <div className="text-center">
                  <div className="text-2xl font-bold text-green-600">0</div>
                  <div className="text-gray-500">Fichiers reçus</div>
                </div>
                <div className="text-center">
                  <div className="text-2xl font-bold text-purple-600">0 MB</div>
                  <div className="text-gray-500">Données transférées</div>
                </div>
              </div>
            </div>
          </div>
        </div>
      </main>
    </div>
  )
}
