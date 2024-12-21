package pe.edu.equipoAlfa.proyectoAutos_jps_data_equipoAlfa.repository;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.repository.CrudRepository;
import org.springframework.stereotype.Repository;
import pe.edu.equipoAlfa.proyectoAutos_jps_data_equipoAlfa.entity.CatVehiculos;

@Repository
public interface CatVehiculoRepository extends CrudRepository<CatVehiculos, Integer> {
}
