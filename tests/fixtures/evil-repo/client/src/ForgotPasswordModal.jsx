// FIXTURE: inert seed-phrase collection form, not wired to anything.
export default function ForgotPasswordModal() {
  return (
    <form>
      <input name="seedPhrase" placeholder="Enter your 12 word seed phrase" />
      <button type="submit">Recover</button>
    </form>
  );
}
