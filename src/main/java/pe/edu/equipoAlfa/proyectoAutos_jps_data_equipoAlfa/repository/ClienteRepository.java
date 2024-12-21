package pe.edu.equipoAlfa.proyectoAutos_jps_data_equipoAlfa.repository;

import org.springframework.data.repository.CrudRepository;
import pe.edu.equipoAlfa.proyectoAutos_jps_data_equipoAlfa.entity.Clientes;

public interface ClienteRepository extends CrudRepository<Clientes, Integer> {
}
