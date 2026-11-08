using UnityEngine;

namespace Game
{
    public sealed class Player : MonoBehaviour
    {
        public float speed = 2f;

        private void Update()
        {
            transform.position += Vector3.right * (speed * Time.deltaTime);
        }
    }
}
