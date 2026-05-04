import firestore, {
  FirebaseFirestoreTypes,
} from '@react-native-firebase/firestore';

export type Doc<T> = T & { id: string };

export const db = firestore();

export async function getDoc<T>(
  path: string,
): Promise<Doc<T> | null> {
  const snap = await db.doc(path).get();
  if (!snap.exists) return null;
  return { id: snap.id, ...(snap.data() as T) };
}

export async function listCollection<T>(
  path: string,
  build?: (
    q: FirebaseFirestoreTypes.CollectionReference,
  ) => FirebaseFirestoreTypes.Query,
): Promise<Doc<T>[]> {
  const ref = db.collection(path);
  const q = build ? build(ref) : ref;
  const snap = await q.get();
  return snap.docs.map(d => ({ id: d.id, ...(d.data() as T) }));
}
