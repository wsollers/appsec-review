using UnityEngine;

public sealed class Boot : MonoBehaviour
{
    private void Start() { Debug.Log(Acme.Tools.Clamp.To(5, 3)); }
}
