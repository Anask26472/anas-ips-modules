from ips.core.feature_builder import build_model_vector


class DummyEncoder:
    classes_ = ['tcp', 'http', 'SF']

    def transform(self, values):
        return [0 for _ in values]


def test_build_model_vector_shape():
    encoders = {'protocol_type': DummyEncoder(), 'service': DummyEncoder(), 'flag': DummyEncoder()}
    features = {
        'duration': 0,
        'protocol_type': 'tcp',
        'service': 'http',
        'flag': 'SF',
        'src_bytes': 100,
        'dst_bytes': 0,
        'land': 0,
        'wrong_fragment': 0,
        'urgent': 0,
        'count': 5,
        'srv_count': 5,
        'serror_rate': 0.0,
        'srv_serror_rate': 0.0,
        'rerror_rate': 0.0,
        'srv_rerror_rate': 0.0,
        'same_srv_rate': 1.0,
        'diff_srv_rate': 0.0,
        'dst_host_srv_diff_host_rate': 0.1,
        'dst_host_count': 2,
        'dst_host_srv_count': 5,
        'dst_host_same_srv_rate': 1.0,
        'dst_host_diff_srv_rate': 0.0,
        'dst_host_same_src_port_rate': 0.5,
        'dst_host_serror_rate': 0.0,
        'dst_host_srv_serror_rate': 0.0,
        'dst_host_rerror_rate': 0.0,
        'dst_host_srv_rerror_rate': 0.0,
    }
    vector = build_model_vector(features, encoders)
    assert vector.shape == (1, 41)
