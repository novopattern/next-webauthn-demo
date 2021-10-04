import styles from '../styles/Home.module.css'
import { signIn, signOut, useSession } from 'next-auth/react';
import { startRegistration } from '@simplewebauthn/browser';

export default function Home() {
    const { data: session, status } = useSession({
        required: true, onUnauthenticated() {
            return signIn();
        }
    });

    async function registerWebauthn() {
        const optionsResponse = await fetch('/api/auth/webauthn/register');
        if (optionsResponse.status !== 200) {
            alert('Could not get registration options from server');
            return;
        }
        const opt = await optionsResponse.json();

        try {
            const credential = await startRegistration(opt)

            const response = await fetch('/api/auth/webauthn/register', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                },
                body: JSON.stringify(credential),
                credentials: 'include'
            });
            if (response.status != 201) {
                alert('Could not register webauthn credentials.');
            } else {
                alert('Your webauthn credentials have been registered.')
            }
        } catch (err) {
            alert(`Registration failed. ${(err as Error).message}`);
        }

    }

    if (status === 'authenticated') {
        return (
            <div className={styles.container}>

                <main className={styles.main}>
                    <h1 className={styles.title}>
                        Welcome to <a href="https://webauthn.guide/" target="_blank"
                                      rel="noopener noreferrer">Webauthn</a> Demo
                    </h1>
                    <button onClick={registerWebauthn}>Register Webauthn</button>

                    <span>Signed in as {session?.user?.email}</span>
                    <button onClick={() => signOut()}>Log out</button>
                </main>
            </div>
        );
    }
    return <div className={styles.container}>Loading...</div>;
}